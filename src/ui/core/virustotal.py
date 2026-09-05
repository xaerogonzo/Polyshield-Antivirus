import hashlib
import json
import threading
import urllib.request
import urllib.error

_VT_BASE = "https://www.virustotal.com/api/v3"


def hash_file(path: str) -> dict[str, str]:
    """Return MD5, SHA1, SHA256 hashes for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception as exc:
        return {"error": str(exc)}


def lookup_hash(sha256: str, api_key: str) -> dict:
    """
    Query VirusTotal for a file hash.
    Returns the parsed JSON response or {'error': '...'} on failure.
    """
    if not api_key:
        return {"error": "No API key configured. Add your VirusTotal API key in Settings."}
    url = f"{_VT_BASE}/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"error": "File not found in VirusTotal database (never submitted)."}
        if exc.code == 401:
            return {"error": "Invalid API key. Check your key in Settings."}
        if exc.code == 429:
            return {"error": "Rate limit exceeded. Free tier allows 4 requests/minute."}
        return {"error": f"HTTP {exc.code}: {exc.reason}"}
    except Exception as exc:
        return {"error": str(exc)}


def lookup_hash_async(sha256: str, api_key: str, callback):
    """Run lookup_hash in a background thread and call callback(result)."""
    def _run():
        result = lookup_hash(sha256, api_key)
        callback(result)
    threading.Thread(target=_run, daemon=True).start()


def parse_result(vt_response: dict) -> dict:
    """
    Extract a clean summary from a VirusTotal API v3 file report.
    Returns dict with keys: malicious, suspicious, undetected, total,
    detections (list of {engine, result}), name, sha256.
    """
    if "error" in vt_response:
        return vt_response

    try:
        attrs = vt_response["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values())

        detections = [
            {"engine": engine, "result": info.get("result", "—")}
            for engine, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        ]
        detections.sort(key=lambda x: x["engine"])

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "total": total,
            "detections": detections,
            "name": attrs.get("meaningful_name", attrs.get("name", "")),
            "sha256": attrs.get("sha256", ""),
            "type": attrs.get("type_description", ""),
            "size": attrs.get("size", 0),
        }
    except (KeyError, TypeError, AttributeError) as exc:
        # AttributeError belongs here for the same reason as the other two: a
        # null "attributes", or a stats/results block that arrives as a list,
        # makes .get()/.items()/.values() the thing that fails rather than the
        # subscript. virustotal_view calls this straight from a Tk callback, so
        # anything that escapes leaves the results panel empty and the button
        # stuck on "Querying…" with no error shown anywhere.
        return {"error": f"Unexpected response format: {exc}"}
