"""Tests for src/shards.py — band naming, byte-stable writes, idempotency."""
import os

from src import parse, shards
from src.shards import ShardConfig


def mkrow(cve_id, **over):
    r = {c: "" for c in parse.COLUMNS}
    r["cve_id"] = cve_id
    r.update(over)
    return r


# ---------------------------------------------------------------------------
# band naming
# ---------------------------------------------------------------------------
def test_band_naming_three_bands():
    cfg = ShardConfig(band_uppers=[2021, 2024])
    assert shards.shard_name_for("CVE-2015-1", cfg) == "cve_2021_and_before"
    assert shards.shard_name_for("CVE-2021-9999", cfg) == "cve_2021_and_before"
    assert shards.shard_name_for("CVE-2022-1", cfg) == "cve_2022_to_2024"
    assert shards.shard_name_for("CVE-2024-38595", cfg) == "cve_2022_to_2024"
    assert shards.shard_name_for("CVE-2025-1", cfg) == "cve_2025_and_after"
    assert shards.shard_name_for("CVE-2030-1", cfg) == "cve_2025_and_after"


def test_band_name_for_boundaries():
    assert shards.band_name_for(2021, [2021, 2024]) == "cve_2021_and_before"
    assert shards.band_name_for(2022, [2021, 2024]) == "cve_2022_to_2024"
    assert shards.band_name_for(2024, [2021, 2024]) == "cve_2022_to_2024"
    assert shards.band_name_for(2025, [2021, 2024]) == "cve_2025_and_after"
    # a single boundary -> two bands
    assert shards.band_name_for(2017, [2017]) == "cve_2017_and_before"
    assert shards.band_name_for(2018, [2017]) == "cve_2018_and_after"


def test_shardconfig_tolerates_bad_band_uppers():
    assert ShardConfig(band_uppers=None).band_uppers == [2021, 2024]
    assert ShardConfig(band_uppers="2021,2024").band_uppers == [2021, 2024]   # str -> default
    assert ShardConfig(band_uppers=[2021, "x", 2024]).band_uppers == [2021, 2024]
    assert ShardConfig(band_uppers=[2024, 2021]).band_uppers == [2021, 2024]  # sorted


# ---------------------------------------------------------------------------
# round-trip + byte stability
# ---------------------------------------------------------------------------
def test_write_read_roundtrip(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2022_to_2024.csv")
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
    rows_a, rows_b = {}, {}
    for cid in ["CVE-2024-2", "CVE-2024-10", "CVE-2024-1"]:
        shards.upsert(rows_a, mkrow(cid))
    for cid in ["CVE-2024-1", "CVE-2024-2", "CVE-2024-10"]:
        shards.upsert(rows_b, mkrow(cid))
    b1, b2 = shards.write_shard(p1, rows_a), shards.write_shard(p2, rows_b)
    assert b1 == b2
    assert open(p1, "rb").read() == open(p2, "rb").read()


def test_natural_sort_orders_by_sequence_not_lexically(tmp_path):
    import csv
    path = os.path.join(tmp_path, "s.csv")
    rows = {c: mkrow(c) for c in ["CVE-2024-2", "CVE-2024-10", "CVE-2024-1"]}
    shards.write_shard(path, rows)
    order = [r["cve_id"] for r in csv.DictReader(open(path, newline=""))]
    assert order == ["CVE-2024-1", "CVE-2024-2", "CVE-2024-10"]


# ---------------------------------------------------------------------------
# idempotency (the §5 requirement)
# ---------------------------------------------------------------------------
def test_idempotent_double_apply_same_bytes(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2022_to_2024.csv")
    batch = [mkrow("CVE-2024-1", cvss_base_score="7.8"),
             mkrow("CVE-2024-2"), mkrow("CVE-2024-3")]

    rows = shards.read_shard(path)
    for r in batch:
        shards.upsert(rows, r)
    shards.write_shard(path, rows)
    first = open(path, "rb").read()

    rows2 = shards.read_shard(path)
    for r in batch:
        shards.upsert(rows2, r)
    shards.write_shard(path, rows2)
    second = open(path, "rb").read()

    assert first == second
    assert len(shards.read_shard(path)) == 3


def test_remove_deletes_row_and_empty_shard_file(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2022_to_2024.csv")
    rows = {c: mkrow(c) for c in ["CVE-2024-1", "CVE-2024-2"]}
    shards.write_shard(path, rows)
    assert shards.remove(rows, "CVE-2024-1") is True
    assert shards.remove(rows, "CVE-2024-404") is False
    shards.write_shard(path, rows)
    assert set(shards.read_shard(path)) == {"CVE-2024-2"}
    shards.remove(rows, "CVE-2024-2")
    shards.write_shard(path, rows)
    assert not os.path.exists(path)


def test_huge_field_roundtrips(tmp_path):
    # a kernel-style description larger than csv's default 128 KB field limit
    path = os.path.join(tmp_path, "shards", "cve_2022_to_2024.csv")
    big = "stacktrace " * 20000  # ~220 KB
    rows = {"CVE-2024-1": mkrow("CVE-2024-1", description_en=big)}
    shards.write_shard(path, rows)
    back = shards.read_shard(path)
    assert back["CVE-2024-1"]["description_en"] == big
    assert shards.stats_from_file(path)["rows"] == 1


def test_stats_and_stats_from_file_agree(tmp_path):
    path = os.path.join(tmp_path, "shards", "cve_2022_to_2024.csv")
    rows = {c: mkrow(c) for c in ["CVE-2024-5", "CVE-2023-100", "CVE-2022-2"]}
    nbytes = shards.write_shard(path, rows)
    s_mem = shards.stats(rows, nbytes)
    s_file = shards.stats_from_file(path)
    assert s_mem == s_file
    assert s_mem["rows"] == 3
    assert s_mem["year_min"] == 2022 and s_mem["year_max"] == 2024
    assert s_mem["bytes"] == nbytes
