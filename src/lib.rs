use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

mod cipher_map;
mod error;
mod http_client;
mod profile;
mod response;
mod tls_builder;

use profile::BrowserProfile;
use response::RustResponse;

// ─────────────────────────────────────────────
// PyBrowserProfile
// ─────────────────────────────────────────────

#[pyclass(name = "BrowserProfile")]
#[derive(Clone)]
pub struct PyBrowserProfile {
    pub inner: BrowserProfile,
}

#[pymethods]
impl PyBrowserProfile {
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    fn __repr__(&self) -> String {
        format!("BrowserProfile(name={:?})", self.inner.name)
    }
}

// ─────────────────────────────────────────────
// PyResponse — requests.Response-compatible
// ─────────────────────────────────────────────

#[pyclass(name = "Response")]
pub struct PyResponse {
    inner: RustResponse,
}

impl PyResponse {
    fn from_rust(r: RustResponse) -> Self {
        Self { inner: r }
    }
}

#[pymethods]
impl PyResponse {
    #[getter]
    fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    #[getter]
    fn url(&self) -> &str {
        &self.inner.url
    }

    #[getter]
    fn content(&self) -> Vec<u8> {
        self.inner.body.clone()
    }

    #[getter]
    fn text(&self) -> PyResult<String> {
        String::from_utf8(self.inner.body.clone()).map_err(|e| {
            pyo3::exceptions::PyUnicodeDecodeError::new_err(e.to_string())
        })
    }

    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let s = std::str::from_utf8(&self.inner.body)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let v: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        json_to_py(py, &v)
    }

    #[getter]
    fn headers(&self) -> HashMap<String, String> {
        self.inner.headers.clone()
    }

    #[getter]
    fn ok(&self) -> bool {
        self.inner.status_code < 400
    }

    fn raise_for_status(&self) -> PyResult<()> {
        if self.inner.status_code >= 400 {
            Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "{} Error for url: {}",
                self.inner.status_code, self.inner.url
            )))
        } else {
            Ok(())
        }
    }

    fn __repr__(&self) -> String {
        format!("<Response [{}]>", self.inner.status_code)
    }
}

fn json_to_py<'py>(py: Python<'py>, v: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    use pyo3::types::PyString;
    match v {
        serde_json::Value::Null => Ok(py.None().into_bound(py)),
        serde_json::Value::Bool(b) => Ok((*b).into_py(py).into_bound(py)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py).into_bound(py))
            } else {
                Ok(n.as_f64().unwrap_or(f64::NAN).into_py(py).into_bound(py))
            }
        }
        serde_json::Value::String(s) => Ok(PyString::new_bound(py, s.as_str()).into_any()),
        serde_json::Value::Array(arr) => {
            let items: PyResult<Vec<_>> = arr.iter().map(|x| json_to_py(py, x)).collect();
            Ok(PyList::new_bound(py, items?).into_any())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, val) in map {
                dict.set_item(k, json_to_py(py, val)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

// ─────────────────────────────────────────────
// PyBrowserSession
// ─────────────────────────────────────────────

#[pyclass(name = "BrowserSession")]
pub struct PyBrowserSession {
    profile: Arc<BrowserProfile>,
    proxy: Option<String>,
    verify: bool,
    ca_bundle: Option<String>,
    session_cookies: Arc<Mutex<HashMap<String, String>>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyBrowserSession {
    #[new]
    #[pyo3(signature = (profile, proxy=None, verify=true, ca_bundle=None))]
    fn new(
        profile: &PyBrowserProfile,
        proxy: Option<String>,
        verify: bool,
        ca_bundle: Option<String>,
    ) -> PyResult<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            profile: Arc::new(profile.inner.clone()),
            proxy,
            verify,
            ca_bundle,
            session_cookies: Arc::new(Mutex::new(HashMap::new())),
            runtime: Arc::new(runtime),
        })
    }

    /// GET request.
    #[pyo3(signature = (url, headers=None, params=None))]
    fn get(
        &self,
        url: String,
        headers: Option<HashMap<String, String>>,
        params: Option<HashMap<String, String>>,
    ) -> PyResult<PyResponse> {
        self.request("GET", url, headers, params, None, None)
    }

    /// POST request.
    #[pyo3(signature = (url, headers=None, params=None, data=None, json=None))]
    fn post(
        &self,
        url: String,
        headers: Option<HashMap<String, String>>,
        params: Option<HashMap<String, String>>,
        data: Option<Vec<u8>>,
        json: Option<HashMap<String, String>>,
    ) -> PyResult<PyResponse> {
        let body = resolve_post_body(data, json)?;
        self.request("POST", url, headers, params, Some(body), None)
    }

    /// Generic request.
    #[pyo3(signature = (method, url, headers=None, params=None, body=None, json=None))]
    fn request(
        &self,
        method: &str,
        url: String,
        headers: Option<HashMap<String, String>>,
        params: Option<HashMap<String, String>>,
        body: Option<Vec<u8>>,
        json: Option<HashMap<String, String>>,
    ) -> PyResult<PyResponse> {
        let final_url = append_params(&url, params.as_ref());
        let mut all_headers = self.build_default_headers(&final_url);

        // Merge user-supplied headers: override existing entries (case-insensitive),
        // append new ones at the end so order stays deterministic.
        if let Some(extra) = headers {
            for (k, v) in extra {
                let k_lower = k.to_lowercase();
                if let Some(entry) = all_headers
                    .iter_mut()
                    .find(|(key, _)| key.eq_ignore_ascii_case(&k_lower))
                {
                    entry.1 = v;
                } else {
                    all_headers.push((k_lower, v));
                }
            }
        }

        let body = if body.is_some() {
            body
        } else if let Some(ref j) = json {
            if let Some(entry) = all_headers
                .iter_mut()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                entry.1 = "application/json".to_owned();
            } else {
                all_headers.push(("content-type".to_owned(), "application/json".to_owned()));
            }
            Some(
                serde_json::to_vec(j)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?,
            )
        } else {
            None
        };

        let profile = Arc::clone(&self.profile);
        let proxy = self.proxy.clone();
        let verify = self.verify;
        let ca_bundle = self.ca_bundle.clone();

        let result = self
            .runtime
            .block_on(http_client::execute(
                method,
                &final_url,
                all_headers,
                body,
                &profile,
                proxy.as_deref(),
                verify,
                ca_bundle.as_deref(),
            ))
            .map_err(|e| Into::<pyo3::PyErr>::into(e))?;

        // Persist Set-Cookie headers into session cookie store
        let sc_value = result.headers.get("set-cookie")
            .or_else(|| result.headers.get("Set-Cookie"))
            .cloned();
        if let Some(sc) = sc_value {
            for cookie in sc.split(',') {
                if let Some((name_val, _)) = cookie.split_once(';') {
                    if let Some((name, value)) = name_val.split_once('=') {
                        self.session_cookies
                            .lock()
                            .unwrap()
                            .insert(name.trim().to_owned(), value.trim().to_owned());
                    }
                }
            }
        }

        Ok(PyResponse::from_rust(result))
    }

    /// Update or add session-level headers/cookies that are sent on every request.
    fn update_cookies(&self, cookies: HashMap<String, String>) {
        self.session_cookies.lock().unwrap().extend(cookies);
    }

    #[getter]
    fn profile_name(&self) -> &str {
        &self.profile.name
    }
}

impl PyBrowserSession {
    fn build_default_headers(&self, _url: &str) -> Vec<(String, String)> {
        let p = &*self.profile;

        // Map a header name to its value from the profile
        let resolve = |name: &str| -> Option<String> {
            match name {
                "user-agent"      => Some(p.user_agent.clone()),
                "accept"          => Some(p.headers.accept.clone()),
                "accept-language" => Some(p.headers.accept_language.clone()),
                "accept-encoding" => Some(p.headers.accept_encoding.clone()),
                other             => p.headers.extra.get(other).cloned(),
            }
        };

        let mut out: Vec<(String, String)> = Vec::new();

        if p.headers.order.is_empty() {
            // Fallback: no order defined, emit the four base headers
            out.push(("user-agent".to_owned(),      p.user_agent.clone()));
            out.push(("accept".to_owned(),           p.headers.accept.clone()));
            out.push(("accept-language".to_owned(),  p.headers.accept_language.clone()));
            out.push(("accept-encoding".to_owned(),  p.headers.accept_encoding.clone()));
        } else {
            for name in &p.headers.order {
                if let Some(value) = resolve(name) {
                    out.push((name.clone(), value));
                }
            }
        }

        // Inject session cookies at the end
        let cookies = self.session_cookies.lock().unwrap();
        if !cookies.is_empty() {
            let cookie_str = cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            out.push(("cookie".to_owned(), cookie_str));
        }

        out
    }
}

fn append_params(url: &str, params: Option<&HashMap<String, String>>) -> String {
    let Some(p) = params else {
        return url.to_owned();
    };
    if p.is_empty() {
        return url.to_owned();
    }
    let query: String = p
        .iter()
        .map(|(k, v)| format!("{}={}", encode_uri(k), encode_uri(v)))
        .collect::<Vec<_>>()
        .join("&");
    if url.contains('?') {
        format!("{url}&{query}")
    } else {
        format!("{url}?{query}")
    }
}

fn encode_uri(s: &str) -> String {
    // Minimal percent-encoding for query params
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || "-._~".contains(c) {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect()
            }
        })
        .collect()
}

fn resolve_post_body(
    data: Option<Vec<u8>>,
    json: Option<HashMap<String, String>>,
) -> PyResult<Vec<u8>> {
    if let Some(d) = data {
        return Ok(d);
    }
    if let Some(j) = json {
        return serde_json::to_vec(&j)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()));
    }
    Ok(Vec::new())
}

// ─────────────────────────────────────────────
// Top-level functions
// ─────────────────────────────────────────────

#[pyfunction]
fn load_profile(path: &str) -> PyResult<PyBrowserProfile> {
    let inner = BrowserProfile::from_file(path)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBrowserProfile { inner })
}

#[pyfunction]
fn load_profile_json(json: &str) -> PyResult<PyBrowserProfile> {
    let inner = BrowserProfile::from_json(json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(PyBrowserProfile { inner })
}

// ─────────────────────────────────────────────
// Module
// ─────────────────────────────────────────────

#[pymodule]
fn _rust_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBrowserProfile>()?;
    m.add_class::<PyBrowserSession>()?;
    m.add_class::<PyResponse>()?;
    m.add_function(wrap_pyfunction!(load_profile, m)?)?;
    m.add_function(wrap_pyfunction!(load_profile_json, m)?)?;
    Ok(())
}
