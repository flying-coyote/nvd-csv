"""End-to-end build tests with the network stubbed.

A fake clone tree is materialized from the checked-in fixtures; deltaLog and the
record fetch are monkeypatched. No real HTTP, no git.
"""
import json
import os

import pytest

from src import build, parse, shards, sources
from src import state as state_mod

FIXDIR = os.path.join(os.path.dirname(__file__), "fixtures")
REAL = ["CVE-2020-1472", "CVE-2021-44228", "CVE-2024-1086",
        "CVE-2024-38595", "CVE-2025-40039"]


def load_fix(name):
    with open(os.path.join(FIXDIR, name + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


def make_clone(root, records_by_id):
    """Lay records out at cves/<year>/<bucket>/CVE-*.json like the real repo."""
    for cid, rec in records_by_id.items():
        rel = parse.source_path_for(cid)
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
    return root


def deltalog(fetch_time, items=()):
    return [{
        "fetchTime": fetch_time, "numberOfChanges": len(items),
        "new": [], "error": [],
        "updated": [{"cveId": cid, "cveOrgLink": "", "githubLink": f"x://{cid}",
                     "dateUpdated": fetch_time} for cid in items],
    }]


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    clone = tmp_path / "clone"
    readme = tmp_path / "README.md"
    monkeypatch.setattr(sources, "fetch_kev", lambda *a, **k: ({}, "test"))
    monkeypatch.setattr(sources, "shallow_clone",
                        lambda *a, **k: pytest.fail("should not clone"))
    return {"data": str(data), "clone": str(clone), "readme": str(readme),
            "monkeypatch": monkeypatch}


# ---------------------------------------------------------------------------
# FULL
# ---------------------------------------------------------------------------
def test_full_builds_shards_and_skips_rejected(env, monkeypatch):
    records = {cid: load_fix(cid) for cid in REAL}
    records["CVE-2099-20002"] = load_fix("synthetic-rejected")  # must be skipped
    make_clone(env["clone"], records)
    monkeypatch.setattr(sources, "fetch_delta_log",
                        lambda *a, **k: deltalog("2026-06-18T00:00:00.000Z"))

    build.main(["--mode", "full", "--no-kev", "--clone-dir", env["clone"],
                "--keep-clone", "--data-dir", env["data"], "--readme", env["readme"]])

    names = {os.path.splitext(os.path.basename(p))[0]
             for p in shards.list_shard_files(env["data"])}
    assert names == {"cve_2020", "cve_2021", "cve_2024", "cve_2025"}
    assert "cve_2099" not in names  # REJECTED excluded

    st = state_mod.load_state(env["data"])
    assert st["total_rows"] == 5
    assert st["run_mode_last"] == "full"
    assert st["last_processed_fetchTime"] == "2026-06-18T00:00:00.000Z"

    rows_2024 = shards.read_shard(shards.shard_path(env["data"], "cve_2024"))
    assert set(rows_2024) == {"CVE-2024-1086", "CVE-2024-38595"}
    assert rows_2024["CVE-2024-1086"]["cvss_base_score"] == "7.8"


# ---------------------------------------------------------------------------
# DELTA: update, REJECTED removal, idempotency
# ---------------------------------------------------------------------------
def _seed_full(env, monkeypatch, fetch_time="2026-06-18T00:00:00.000Z"):
    make_clone(env["clone"], {cid: load_fix(cid) for cid in REAL})
    monkeypatch.setattr(sources, "fetch_delta_log", lambda *a, **k: deltalog(fetch_time))
    build.main(["--mode", "full", "--no-kev", "--clone-dir", env["clone"],
                "--keep-clone", "--data-dir", env["data"], "--readme", env["readme"]])


def test_full_autosplits_oversized_year(env, monkeypatch):
    make_clone(env["clone"], {cid: load_fix(cid) for cid in REAL})
    monkeypatch.setattr(sources, "fetch_delta_log",
                        lambda *a, **k: deltalog("2026-06-18T00:00:00.000Z"))
    # a 500-byte cap forces every populated year to split into thousand-buckets
    build.main(["--mode", "full", "--no-kev", "--clone-dir", env["clone"],
                "--keep-clone", "--data-dir", env["data"], "--readme", env["readme"],
                "--shard-max-bytes", "500"])
    names = {os.path.splitext(os.path.basename(p))[0]
             for p in shards.list_shard_files(env["data"])}
    # cve_2024 holds CVE-2024-1086 (1xxx) and CVE-2024-38595 (38xxx)
    assert "cve_2024" not in names
    assert {"cve_2024_1xxx", "cve_2024_38xxx"} <= names
    st = state_mod.load_state(env["data"])
    assert 2024 in st["split_years"]
    assert st["total_rows"] == 5  # split changes layout, not row count


def test_delta_removes_record_that_became_rejected(env, monkeypatch):
    _seed_full(env, monkeypatch)
    # CVE-2024-1086 transitions to REJECTED
    rejected = load_fix("synthetic-rejected")
    rejected["cveMetadata"]["cveId"] = "CVE-2024-1086"
    rec_map = {"CVE-2024-1086": rejected}
    monkeypatch.setattr(sources, "fetch_delta_log",
                        lambda *a, **k: deltalog("2026-06-19T00:00:00.000Z",
                                                 ["CVE-2024-1086"]))
    monkeypatch.setattr(sources, "fetch_records",
                        lambda s, changed, **k: ({c: rec_map[c] for c in changed
                                                  if c in rec_map}, {}))
    build.main(["--mode", "delta", "--no-kev", "--data-dir", env["data"],
                "--readme", env["readme"]])

    rows_2024 = shards.read_shard(shards.shard_path(env["data"], "cve_2024"))
    assert "CVE-2024-1086" not in rows_2024            # removed
    assert "CVE-2024-38595" in rows_2024               # untouched
    assert state_mod.load_state(env["data"])["total_rows"] == 4


def test_delta_double_apply_is_idempotent(env, monkeypatch):
    _seed_full(env, monkeypatch)
    seed_cursor = "2026-06-18T00:00:00.000Z"
    updated = load_fix("CVE-2024-1086")  # re-serve same record as an "update"
    rec_map = {"CVE-2024-1086": updated}
    monkeypatch.setattr(sources, "fetch_delta_log",
                        lambda *a, **k: deltalog("2026-06-19T00:00:00.000Z",
                                                 ["CVE-2024-1086"]))
    monkeypatch.setattr(sources, "fetch_records",
                        lambda s, changed, **k: ({c: rec_map[c] for c in changed
                                                  if c in rec_map}, {}))

    path = shards.shard_path(env["data"], "cve_2024")
    build.main(["--mode", "delta", "--no-kev", "--data-dir", env["data"],
                "--readme", env["readme"]])
    bytes_first = open(path, "rb").read()
    total_first = state_mod.load_state(env["data"])["total_rows"]

    # rewind the cursor so the SAME batch is re-applied, then re-run
    st = state_mod.load_state(env["data"])
    st["last_processed_fetchTime"] = seed_cursor
    state_mod.save_state(env["data"], st)
    build.main(["--mode", "delta", "--no-kev", "--data-dir", env["data"],
                "--readme", env["readme"]])
    bytes_second = open(path, "rb").read()
    total_second = state_mod.load_state(env["data"])["total_rows"]

    assert bytes_first == bytes_second       # re-applying changed nothing
    assert total_first == total_second == 5


# ---------------------------------------------------------------------------
# mode decision (staleness guard)
# ---------------------------------------------------------------------------
def test_decide_mode_staleness_guard(tmp_path):
    data = str(tmp_path / "d")
    os.makedirs(os.path.join(data, "shards"), exist_ok=True)
    # no shards yet -> full
    assert build.decide_mode("auto", {"last_processed_fetchTime": "x"}, data, "a") == "full"
    # make a shard exist
    open(os.path.join(data, "shards", "cve_2024.csv"), "w").write("cve_id\n")
    # cursor older than oldest window -> gap -> full
    assert build.decide_mode("auto", {"last_processed_fetchTime": "2026-01-01"},
                             data, "2026-02-01") == "full"
    # cursor within window -> delta
    assert build.decide_mode("auto", {"last_processed_fetchTime": "2026-03-01"},
                             data, "2026-02-01") == "delta"
    # explicit overrides win
    assert build.decide_mode("full", {"last_processed_fetchTime": "2026-03-01"},
                             data, "2026-02-01") == "full"
    assert build.decide_mode("delta", {}, data, "2026-02-01") == "delta"
