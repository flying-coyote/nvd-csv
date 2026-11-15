"""Tests for src/verify.py — restored shards checked against the state.json manifest."""
import os

from src import shards, verify
from src import state as state_mod


def _setup(tmp_path, with_sha=True):
    data = str(tmp_path / "data")
    path = shards.shard_path(data, "cve_2026_to_now")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("cve_id\nCVE-2026-1\n")
    st = state_mod.default_state()
    s = shards.stats_from_file(path)
    if not with_sha:
        s.pop("sha256")
    st["shards"] = {"cve_2026_to_now": s}
    state_mod.save_state(data, st)
    return data, path


def test_matching_shards_are_kept(tmp_path):
    data, path = _setup(tmp_path)
    assert verify.verify(data) == "ok"
    assert os.path.exists(path)


def test_tampered_shard_deletes_all(tmp_path):
    data, path = _setup(tmp_path)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("CVE-2026-2\n")
    assert verify.verify(data) == "mismatch"
    assert shards.list_shard_files(data) == []


def test_missing_shard_is_mismatch(tmp_path):
    data, path = _setup(tmp_path)
    os.remove(path)
    assert verify.verify(data) == "mismatch"


def test_legacy_state_without_sha_leaves_files(tmp_path):
    data, path = _setup(tmp_path, with_sha=False)
    assert verify.verify(data) == "legacy"
    assert os.path.exists(path)


def test_extra_shard_not_in_manifest_is_dropped(tmp_path):
    data, path = _setup(tmp_path)
    extra = shards.shard_path(data, "cve_2021_and_before")
    with open(extra, "w", encoding="utf-8") as fh:
        fh.write("cve_id\n")
    assert verify.verify(data) == "ok"
    assert not os.path.exists(extra) and os.path.exists(path)
