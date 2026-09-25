#!/usr/bin/env python3
"""Wait for and download a named artifact produced by this workflow run."""

import io
import json
import os
import sys
import time
import urllib.request
import zipfile

if len(sys.argv) != 3:
    raise SystemExit("usage: download-run-artifact.py <artifact-name> <destination-dir>")

name, destination = sys.argv[1], sys.argv[2]
repo = os.environ["GITHUB_REPOSITORY"]
run_id = os.environ["GITHUB_RUN_ID"]
token = os.environ["GITHUB_TOKEN"]
api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
deadline = time.time() + int(os.environ.get("ARTIFACT_WAIT_SECONDS", "600"))

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "awl-throughput-ci",
}


def get_json(url):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


while time.time() < deadline:
    payload = get_json(f"{api}/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    matches = [a for a in payload.get("artifacts", []) if a.get("name") == name and not a.get("expired")]
    if matches:
        artifact = max(matches, key=lambda a: a["id"])
        req = urllib.request.Request(artifact["archive_download_url"], headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        os.makedirs(destination, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(destination)
        print(f"downloaded artifact {name} id={artifact['id']} to {destination}")
        raise SystemExit(0)
    print(f"waiting for artifact {name}...")
    time.sleep(5)

raise SystemExit(f"timed out waiting for artifact {name}")
