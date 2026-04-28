from rqsession.rust_session import BrowserSession, Chrome120, Firefox133, Safari17, Edge142


def search_channel_by_keyword(keyword: str, session: BrowserSession) -> dict:
    url = "https://kick.com/api/search"
    params = {"searched_word": keyword}
    headers = {
        "accept": "application/json",
        "referer": f"https://kick.com/search/livestreams?query={keyword}",
    }
    resp = session.get(url, params=params, headers=headers)
    print(f"  status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"  body: {resp.text[:300]}")
        return {}
    data = resp.json()
    channels = data.get("channels", [])
    print(f"  channels returned: {len(channels)}")
    if channels:
        print(f"  first channel: {channels[0].get('slug')} | followers: {channels[0].get('followers_count')}")
    return data


if __name__ == "__main__":
    for name, profile in [
        ("Chrome120", Chrome120),
        ("Firefox133", Firefox133),
        ("Safari17", Safari17),
        ("Edge142", Edge142),
    ]:
        print(f"\n[{name}]")
        with BrowserSession(profile) as s:
            search_channel_by_keyword("rust", s)
