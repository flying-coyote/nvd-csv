"""Shard naming and byte-stable CSV read/upsert/remove.

Sharding is by coarse age band (§7): a small, fixed set of multi-year shards
sized to stay under GitHub's per-file limit, e.g. with band uppers [2022, 2025]:

    cve_2022_and_before.csv   (<= 2022)
    cve_2023_to_2025.csv      (2023..2025)
    cve_2026_to_now.csv       (>= 2026)

Bands keep the shard count low at the cost of larger files; there is no
auto-split. build.py warns loudly if any shard exceeds ``shard_max_bytes`` so
the band uppers can be re-tuned (lower a boundary to peel the oldest years off).

Byte-stability is the backbone of idempotency: a shard is always serialized with
rows sorted by (year, sequence), QUOTE_MINIMAL, '\\n' endings, UTF-8 — so the
same set of rows always produces the same bytes regardless of upsert order.
"""

from __future__ import annotations

import csv
import glob
import io
import os
import sys

from .parse import COLUMNS, year_of

# CVE descriptions (especially Linux-kernel records with embedded stack traces)
# can exceed Python's default 128 KB CSV field limit on read-back. Raise it to
# the largest value this platform's C long accepts.
_csv_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_csv_limit)
        break
    except OverflowError:
        _csv_limit //= 10

DEFAULT_BAND_UPPERS = [2022, 2025]              # -> 3 shards
DEFAULT_SHARD_MAX_BYTES = 90 * 1024 * 1024      # 90 MB, under GitHub's 100


class ShardConfig:
    def __init__(self, band_uppers=None, shard_max_bytes=DEFAULT_SHARD_MAX_BYTES):
        ups = band_uppers if band_uppers is not None else DEFAULT_BAND_UPPERS
        if not isinstance(ups, (list, tuple, set)):
            ups = DEFAULT_BAND_UPPERS
        clean = []
        for u in ups:
            try:
                clean.append(int(u))
            except (TypeError, ValueError):
                continue
        self.band_uppers = sorted(set(clean)) or list(DEFAULT_BAND_UPPERS)
        self.shard_max_bytes = int(shard_max_bytes)


# ---------------------------------------------------------------------------
# naming
# ---------------------------------------------------------------------------
def band_name_for(year, uppers) -> str:
    """Map a year to its band shard name given ascending band upper bounds."""
    year = int(year)
    if year <= uppers[0]:
        return f"cve_{uppers[0]}_and_before"
    for i in range(1, len(uppers)):
        if year <= uppers[i]:
            return f"cve_{uppers[i - 1] + 1}_to_{uppers[i]}"
    return f"cve_{uppers[-1] + 1}_to_now"


def shard_name_for(cve_id: str, cfg: ShardConfig) -> str:
    return band_name_for(int(year_of(cve_id)), cfg.band_uppers)


def shard_path(data_dir: str, name: str) -> str:
    return os.path.join(data_dir, "shards", f"{name}.csv")


def list_shard_files(data_dir: str):
    return sorted(glob.glob(os.path.join(data_dir, "shards", "*.csv")))


# ---------------------------------------------------------------------------
# sort + (de)serialize
# ---------------------------------------------------------------------------
def sort_key(cve_id: str):
    try:
        _, year, seq = cve_id.split("-", 2)
        return (int(year), int(seq), cve_id)
    except (ValueError, AttributeError):
        return (10 ** 9, 10 ** 9, cve_id)


def serialize(rows_by_id: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, quoting=csv.QUOTE_MINIMAL,
                            lineterminator="\n")
    writer.writeheader()
    for cve_id in sorted(rows_by_id, key=sort_key):
        writer.writerow(rows_by_id[cve_id])
    return buf.getvalue().encode("utf-8")


def read_shard(path: str) -> dict:
    rows = {}
    if not os.path.exists(path):
        return rows
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rows[row["cve_id"]] = row
    return rows


def write_shard(path: str, rows_by_id: dict) -> int:
    """Write (sorted, byte-stable). Empty shard -> delete the file. Returns bytes."""
    if not rows_by_id:
        if os.path.exists(path):
            os.remove(path)
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = serialize(rows_by_id)
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# ---------------------------------------------------------------------------
# upsert / remove (keyed solely on cve_id)
# ---------------------------------------------------------------------------
def upsert(rows_by_id: dict, row: dict) -> None:
    rows_by_id[row["cve_id"]] = row


def remove(rows_by_id: dict, cve_id: str) -> bool:
    return rows_by_id.pop(cve_id, None) is not None


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
def stats(rows_by_id: dict, nbytes: int | None = None) -> dict:
    years = [sort_key(c)[0] for c in rows_by_id]
    return {
        "rows": len(rows_by_id),
        "bytes": nbytes if nbytes is not None else len(serialize(rows_by_id)),
        "year_min": min(years) if years else None,
        "year_max": max(years) if years else None,
    }


def stats_from_file(path: str) -> dict:
    """Cheap on-disk stats without holding all rows: stream the file once."""
    rows = 0
    ymin = ymax = None
    nbytes = os.path.getsize(path) if os.path.exists(path) else 0
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                rows += 1
                try:
                    y = int(row.get("cve_id", "").split("-")[1])
                except (ValueError, IndexError):
                    continue  # malformed id: count the row, skip the year math
                ymin = y if ymin is None else min(ymin, y)
                ymax = y if ymax is None else max(ymax, y)
    return {"rows": rows, "bytes": nbytes, "year_min": ymin, "year_max": ymax}
