"""Bounded benign private-object smoke check; never collects or executes samples."""
import hashlib
import json
import urllib.error
import urllib.request

from secopsai.research_artifact_vault import NoRedirect, USER_AGENT, VaultClient


def main():
    client = VaultClient(seconds=60)
    body = b"SecOpsAI immutable storage protocol smoke fixture v1.\n"
    sha = client.put(body)
    if client.put(body) != sha or client.get(sha) != body:
        raise ValueError("immutable storage round trip failed")
    try:
        request = urllib.request.Request(client.url + "/artifact-objects/" + sha, headers={"User-Agent": USER_AGENT})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15):
            pass
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise ValueError("private object access contract failed") from None
    else:
        raise ValueError("private object was accessible without authentication")
    wrong = hashlib.sha256(b"intentionally different checksum fixture").hexdigest()
    try:
        client.request("PUT", wrong, body)
    except ValueError as error:
        if str(error) != "artifact vault HTTP 400":
            raise ValueError("checksum rejection contract failed") from None
    else:
        raise ValueError("invalid checksum was accepted")
    print(json.dumps({"status": "passed", "sha256": sha, "bytes": len(body), "scope": "benign synthetic immutable object, repeated delivery, private access and checksum rejection"}))


if __name__ == "__main__":
    # Errors exclude request bodies and authentication headers.
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "failed", "error_category": type(error).__name__}))
        raise SystemExit(1)
