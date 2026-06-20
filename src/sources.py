"""Upstream I/O: deltaLog, concurrent raw record fetches, KEV catalog, full clone.

Network is isolated here so build.py stays testable. ``requests`` is the only
non-stdlib runtime dependency (allowed per the brief); retries use urllib3's
Retry with exponential backoff.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 ships with requests; this import path is stable across 1.x/2.x
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
DELTALOG_URL = RAW_BASE + "cves/deltaLog.json"
DELTA_URL = RAW_BASE + "cves/delta.json"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
CLONE_URL = "https://github.com/CVEProject/cvelistV5.git"

USER_AGENT = "nvd-csv (https://github.com/; daily CVE CSV builder)"


# ---------------------------------------------------------------------------
# HTTP session with retries
# ---------------------------------------------------------------------------
def make_session(retries: int = 5, backoff: float = 0.5) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries, connect=retries, read=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def get_json(session, url, timeout=60):
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# deltaLog
# ---------------------------------------------------------------------------
def fetch_delta_log(session, timeout=120):
    return get_json(session, DELTALOG_URL, timeout)


def deltalog_bounds(deltalog):
    """(oldest, newest) fetchTime actually present — never assume a fixed window."""
    times = [d.get("fetchTime") for d in deltalog if d.get("fetchTime")]
    if not times:
        return None, None
    return min(times), max(times)


def changes_since(deltalog, last_processed):
    """Union new[]+updated[] for delta objects newer than last_processed.

    Returns ({cveId: githubLink}, [error items]). githubLink is the stable raw
    path for a CVE, so de-duplicating by cveId is safe.
    """
    changed = {}
    errors = []
    for delta in deltalog:
        fetch_time = delta.get("fetchTime")
        if last_processed is not None and fetch_time is not None \
                and fetch_time <= last_processed:
            continue
        for item in (delta.get("new") or []) + (delta.get("updated") or []):
            cid, link = item.get("cveId"), item.get("githubLink")
            if cid and link:
                changed[cid] = link
        errors.extend(delta.get("error") or [])
    return changed, errors


# ---------------------------------------------------------------------------
# raw record fetches (concurrent)
# ---------------------------------------------------------------------------
def fetch_record(session, url, timeout=30):
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def fetch_records(session, cve_to_url, max_workers=12, timeout=30):
    """Concurrently fetch raw records. Returns ({cveId: record}, {cveId: error})."""
    results, errors = {}, {}

    def work(item):
        cid, url = item
        try:
            return cid, fetch_record(session, url, timeout), None
        except Exception as exc:  # network/json error -> recorded, not fatal
            return cid, None, f"{type(exc).__name__}: {exc}"

    if not cve_to_url:
        return results, errors
    workers = max(1, min(max_workers, len(cve_to_url)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for cid, record, err in pool.map(work, list(cve_to_url.items())):
            if err is None:
                results[cid] = record
            else:
                errors[cid] = err
    return results, errors


# ---------------------------------------------------------------------------
# KEV catalog
# ---------------------------------------------------------------------------
def fetch_kev(session, timeout=60):
    """Return ({cveID: {dateAdded, knownRansomwareCampaignUse}}, catalog_date)."""
    data = get_json(session, KEV_URL, timeout)
    index = {}
    for vuln in data.get("vulnerabilities", []):
        cid = vuln.get("cveID")
        if cid:
            index[cid] = {
                "dateAdded": vuln.get("dateAdded", ""),
                "knownRansomwareCampaignUse":
                    vuln.get("knownRansomwareCampaignUse", ""),
            }
    catalog_date = data.get("dateReleased") or data.get("catalogVersion")
    return index, catalog_date


# ---------------------------------------------------------------------------
# full acquisition
# ---------------------------------------------------------------------------
def shallow_clone(dest, url=CLONE_URL, timeout=1800):
    """Full-rebuild acquisition: git clone --depth 1. Returns the dest path.

    (The daily *_all_CVEs_at_midnight.zip GitHub Release is a lighter
    alternative, not implemented here.)"""
    subprocess.run(
        ["git", "clone", "--depth", "1", "--no-tags", url, dest],
        check=True, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return dest


def year_dirs(repo_dir):
    """Sorted (descending) 4-digit year directory names under cves/."""
    cves_root = os.path.join(repo_dir, "cves")
    if not os.path.isdir(cves_root):
        return []
    years = [d for d in os.listdir(cves_root)
             if d.isdigit() and os.path.isdir(os.path.join(cves_root, d))]
    return sorted(years, reverse=True)


def load_record(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
