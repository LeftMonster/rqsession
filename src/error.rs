use pyo3::exceptions::{PyConnectionError, PyRuntimeError, PyValueError};
use pyo3::PyErr;

#[derive(Debug)]
pub enum Error {
    InvalidUrl(String),
    Tls(String),
    Http(String),
    Io(String),
    InvalidProfile(String),
    TooManyRedirects,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidUrl(s)      => write!(f, "Invalid URL: {}", s),
            Error::Tls(s)             => write!(f, "TLS error: {}", s),
            Error::Http(s)            => write!(f, "HTTP error: {}", s),
            Error::Io(s)              => write!(f, "IO error: {}", s),
            Error::InvalidProfile(s)  => write!(f, "Invalid profile: {}", s),
            Error::TooManyRedirects   => write!(f, "Too many redirects"),
        }
    }
}

impl From<Error> for PyErr {
    fn from(e: Error) -> PyErr {
        match e {
            Error::InvalidUrl(s)     => PyValueError::new_err(s),
            Error::Tls(s)            => PyConnectionError::new_err(s),
            Error::Http(s)           => PyConnectionError::new_err(s),
            Error::Io(s)             => PyConnectionError::new_err(s),
            Error::InvalidProfile(s) => PyValueError::new_err(s),
            Error::TooManyRedirects  => PyRuntimeError::new_err("Too many redirects"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self { Error::Io(e.to_string()) }
}
