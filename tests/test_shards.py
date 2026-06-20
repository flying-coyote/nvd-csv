"""Tests for src/shards.py — naming, byte-stable writes, idempotency, split."""
import os

import pytest

from src import parse, shards
from src.shards import ShardConfig


def mkrow(cve_id, **over):
    r = {c: "" for c in parse.COLUMNS}
    r["cve_id"] = cve_id
    r.update(over)
    return r


# ---------------------------------------------------------------------------
# naming
# ---------------------------------------------------------------------------
def test_archive_vs_per_year_naming():
    cfg = ShardConfig(archive_cutoff_year=2017)
    assert shards.shard_name_for("CVE-2015-0001", cfg) == "cve_archive_le2017"
    assert shards.shard_name_for("CVE-2017-9999", cfg) == "cve_archive_le2017"
    assert shards.shard_name_for("CVE-2018-0001", cfg) == "cve_2018"
    assert shards.shard_name_for("CVE-2024-38595", cfg) == "cve_2024"


def test_split_year_naming():
    cfg = ShardConfig(archive_cutoff_year=2017, split_years=[2024])
    assert shards.shard_name_for("CVE-2024-38595", cfg) == "cve_2024_38xxx"
    assert shards.shard_name_for("CVE-2024-7", cfg) == "cve_2024_0xxx"
    # other years unaffected
    assert shards.shard_name_for("CVE-2025-1", cfg) == "cve_2025"


def test_shardconfig_tolerates_corrupted_split_years():
    assert shards.ShardConfig(split_years="2024,2025").split_years == set()
    assert shards.ShardConfig(split_years=2024).split_years == set()
    assert shards.ShardConfig(split_years=["2024", 2025, "bad"]).split_years == {2024, 2025}


def test_shard_year_parsing():
    assert shards.shard_year("cve_2024") == 2024
    assert shards.shard_year("cve_2024_38xxx") == 2024
    assert shards.shard_year("cve_archive_le2017") is None


# ---------------------------------------------------------------------------
# round-trip + byte stability
# ---------------------------------------------------------------------------
def test_write_read_roundtrip(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2024.csv")
    rows = {"CVE-2024-1": mkrow("CVE-2024-1", title="a,b \"c\""),
            "CVE-2024-2": mkrow("CVE-2024-2")}
    shards.write_shard(path, rows)
    back = shards.read_shard(path)
    assert set(back) == {"CVE-2024-1", "CVE-2024-2"}
    assert list(back["CVE-2024-1"].keys()) == parse.COLUMNS
    assert back["CVE-2024-1"]["title"] == 'a,b "c"'


def test_bytes_are_insertion_order_independent(tmp_path):
    p1 = os.path.join(tmp_path, "a.csv")
    p2 = os.path.join(tmp_path, "b.csv")
    rows_a = {}
    for cid in ["CVE-2024-2", "CVE-2024-10", "CVE-2024-1"]:
        shards.upsert(rows_a, mkrow(cid))
    rows_b = {}
    for cid in ["CVE-2024-1", "CVE-2024-2", "CVE-2024-10"]:
        shards.upsert(rows_b, mkrow(cid))
    b1, b2 = shards.write_shard(p1, rows_a), shards.write_shard(p2, rows_b)
    assert b1 == b2
    assert open(p1, "rb").read() == open(p2, "rb").read()


def test_natural_sort_orders_by_sequence_not_lexically(tmp_path):
    path = os.path.join(tmp_path, "s.csv")
    rows = {c: mkrow(c) for c in ["CVE-2024-2", "CVE-2024-10", "CVE-2024-1"]}
    shards.write_shard(path, rows)
    order = [r["cve_id"] for r in
             __import__("csv").DictReader(open(path, newline=""))]
    assert order == ["CVE-2024-1", "CVE-2024-2", "CVE-2024-10"]


# ---------------------------------------------------------------------------
# idempotency (the §5 requirement)
# ---------------------------------------------------------------------------
def test_idempotent_double_apply_same_bytes(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2024.csv")
    batch = [mkrow("CVE-2024-1", cvss_base_score="7.8"),
             mkrow("CVE-2024-2"), mkrow("CVE-2024-3")]

    rows = shards.read_shard(path)
    for r in batch:
        shards.upsert(rows, r)
    shards.write_shard(path, rows)
    first = open(path, "rb").read()

    # apply the identical batch again on a fresh read
    rows2 = shards.read_shard(path)
    for r in batch:
        shards.upsert(rows2, r)
    shards.write_shard(path, rows2)
    second = open(path, "rb").read()

    assert first == second
    assert len(shards.read_shard(path)) == 3   # no duplication


def test_remove_deletes_row_and_empty_shard_file(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2024.csv")
    rows = {c: mkrow(c) for c in ["CVE-2024-1", "CVE-2024-2"]}
    shards.write_shard(path, rows)
    assert shards.remove(rows, "CVE-2024-1") is True
    assert shards.remove(rows, "CVE-2024-404") is False
    shards.write_shard(path, rows)
    assert set(shards.read_shard(path)) == {"CVE-2024-2"}
    # remove the last row -> file deleted
    shards.remove(rows, "CVE-2024-2")
    shards.write_shard(path, rows)
    assert not os.path.exists(path)


# ---------------------------------------------------------------------------
# stats + split
# ---------------------------------------------------------------------------
def test_stats_and_stats_from_file_agree(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2024.csv")
    rows = {c: mkrow(c) for c in ["CVE-2024-5", "CVE-2024-100", "CVE-2024-2"]}
    nbytes = shards.write_shard(path, rows)
    s_mem = shards.stats(rows, nbytes)
    s_file = shards.stats_from_file(path)
    assert s_mem == s_file
    assert s_mem["rows"] == 3
    assert s_mem["year_min"] == 2024 and s_mem["year_max"] == 2024
    assert s_mem["bytes"] == nbytes


def test_split_into_buckets():
    rows = {c: mkrow(c) for c in
            ["CVE-2024-38595", "CVE-2024-38001", "CVE-2024-1086", "CVE-2024-7"]}
    out = shards.split_into_buckets(rows, 2024)
    assert set(out) == {"cve_2024_38xxx", "cve_2024_1xxx", "cve_2024_0xxx"}
    assert set(out["cve_2024_38xxx"]) == {"CVE-2024-38595", "CVE-2024-38001"}
    assert set(out["cve_2024_0xxx"]) == {"CVE-2024-7"}


def test_huge_field_roundtrips(tmp_path):
    # a kernel-style description larger than csv's default 128 KB field limit
    path = os.path.join(tmp_path, "shards", "cve_2024.csv")
    big = "stacktrace " * 20000  # ~220 KB
    rows = {"CVE-2024-1": mkrow("CVE-2024-1", description_en=big)}
    shards.write_shard(path, rows)
    back = shards.read_shard(path)
    assert back["CVE-2024-1"]["description_en"] == big
    assert shards.stats_from_file(path)["rows"] == 1


def test_split_threshold_triggers(tmp_path):
    # tiny threshold to force a split decision in build-style logic
    cfg = ShardConfig(shard_max_bytes=200)
    rows = {f"CVE-2024-{i}": mkrow(f"CVE-2024-{i}") for i in range(50)}
    nbytes = len(shards.serialize(rows))
    assert nbytes > cfg.shard_max_bytes  # would trigger a split
    buckets = shards.split_into_buckets(rows, 2024)
    assert "cve_2024_0xxx" in buckets
