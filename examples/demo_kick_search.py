import sys
import json
import warnings

sys.path.insert(0, "D:/ownrepo-github/requestsession/rqsession")

warnings.filterwarnings("ignore", category=UserWarning, module="browser_forge")

from rqsession.browser_forge import BrowserClient, Chrome119, Safari17, Edge142


def search_channel_by_keyword(keyword: str, profile) -> dict:
    url = "https://kick.com/api/search"
    params = {"searched_word": keyword}
    headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "referer": f"https://kick.com/search/livestreams?query={keyword}",
    }
    with BrowserClient(profile, proxy="http://127.0.0.1:7890") as client:
        info = client.get_fingerprint_info()
        print(f"  mode: {info.get('actual_mode')}")
        resp = client.get(url, params=params, headers=headers)
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
    for name, profile in [("Chrome119", Chrome119), ("Safari17", Safari17), ("Edge142", Edge142)]:
        print(f"\n[{name}]")
        search_channel_by_keyword("rust", profile)
