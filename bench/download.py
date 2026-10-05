"""Download one hour of public GitHub events from GH Archive (about 19 MB)."""
import argparse
import pathlib
import urllib.request

DEFAULT_HOUR = "2026-10-01-15"


def download(hour: str = DEFAULT_HOUR, folder: str = "data") -> pathlib.Path:
    target = pathlib.Path(folder) / f"gh-{hour}.json.gz"
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://data.gharchive.org/{hour}.json.gz"
        print(f"downloading {url}")
        request = urllib.request.Request(url, headers={"User-Agent": "pqbatch-bench"})
        with urllib.request.urlopen(request) as response:
            target.write_bytes(response.read())
    return target


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hour", default=DEFAULT_HOUR, help="UTC hour as YYYY-MM-DD-H")
    print(download(ap.parse_args().hour))
