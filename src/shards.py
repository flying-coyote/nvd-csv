"""Shard naming, byte-stable CSV read/upsert/remove, size monitoring, auto-split.

Sharding is by activity/age (§7): one archive shard for years <= cutoff, one
shard per year after. A year that grows past ``shard_max_bytes`` is auto-split
into CVE-ID thousands buckets (cve_2025_0xxx.csv, ...).

Byte-stability is the backbone of the idempotency guarantee: a shard is always
serialized with rows sorted by (year, sequence), QUOTE_MINIMAL, '\\n' endings,
UTF-8 — so the same set of rows always produces the same bytes regardless of
upsert order, and re-running a delta changes nothing.
"""

from __future__ import annotations

import csv
import glob
import io
import os
import re
import sys

from .parse import COLUMNS, bucket_of, year_of

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

DEFAULT_ARCHIVE_CUTOFF_YEAR = 2017
DEFAULT_SHARD_MAX_BYTES = 90 * 1024 * 1024  # 90 MB, comfortably under GitHub's 100

_SPLIT_RE = re.compile(r"^cve_(\d{4})_(\d+)xxx$")
_YEAR_RE = re.compile(r"^cve_(\d{4})$")


class ShardConfig:
    def __init__(self, archive_cutoff_year=DEFAULT_ARCHIVE_CUTOFF_YEAR,
                 shard_max_bytes=DEFAULT_SHARD_MAX_BYTES, split_years=None):
        self.archive_cutoff_year = int(archive_cutoff_year)
        self.shard_max_bytes = int(shard_max_bytes)
        # tolerate a corrupted state.json (e.g. split_years saved as a scalar/str)
        years = split_years if isinstance(split_years, (list, tuple, set)) else []
        clean = set()
        for y in years:
            try:
                clean.add(int(y))
            except (TypeError, ValueError):
                continue
        self.split_years = clean

    @property
    def archive_name(self) -> str:
        return f"cve_archive_le{self.archive_cutoff_year}"


# ---------------------------------------------------------------------------
# naming
# ---------------------------------------------------------------------------
def base_shard_name(year: int, cfg: ShardConfig) -> str:
    """Shard ignoring split state: archive bucket or one-per-year."""
    return cfg.archive_name if int(year) <= cfg.archive_cutoff_year else f"cve_{int(year)}"


def shard_name_for(cve_id: str, cfg: ShardConfig) -> str:
    """Target shard for a CVE, honoring any active split for its year."""
    year = int(year_of(cve_id))
    if year in cfg.split_years and year > cfg.archive_cutoff_year:
        return f"cve_{year}_{bucket_of(cve_id)}"
    return base_shard_name(year, cfg)


def shard_path(data_dir: str, name: str) -> str:
    return os.path.join(data_dir, "shards", f"{name}.csv")


def list_shard_files(data_dir: str):
    return sorted(glob.glob(os.path.join(data_dir, "shards", "*.csv")))


def shard_year(name: str):
    """The year a per-year or split shard covers (None for the archive shard)."""
    m = _SPLIT_RE.match(name) or _YEAR_RE.match(name)
    return int(m.group(1)) if m else None


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
# stats + split
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


def split_into_buckets(rows_by_id: dict, year: int) -> dict:
    """Regroup one year's rows into {bucket_shard_name: {cve_id: row}}."""
    out: dict = {}
    for cve_id, row in rows_by_id.items():
        name = f"cve_{int(year)}_{bucket_of(cve_id)}"
        out.setdefault(name, {})[cve_id] = row
    return out
