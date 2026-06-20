"""CLI entrypoint: decide mode, build/refresh shards, write change log + stats.

    python -m src.build --mode auto|full|delta [--limit N] [--no-commit]
                        [--max-desc-chars N] [--data-dir data]
                        [--band-uppers 2021,2024] [--shard-max-bytes N]

build.py never runs git — the GitHub Actions workflow owns commit/push.
``--no-commit`` is accepted (and is the only behavior) so the documented dry-run
invocation works verbatim.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone

from . import parse, shards, sources, state as state_mod
from .shards import ShardConfig

CHANGE_COLUMNS = ["cve_id", "change_type", "date_updated", "shard", "run_utc"]
README_START = "<!-- STATS:START -->"
README_END = "<!-- STATS:END -->"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------
def _now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def log(msg):
    print(msg, flush=True)


def kev_snapshot_path(data_dir):
    return os.path.join(data_dir, "kev_snapshot.json")


def load_kev_snapshot(data_dir):
    path = kev_snapshot_path(data_dir)
    if not os.path.exists(path):
        return {}
    import json
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_kev_snapshot(data_dir, kev_index):
    import json
    os.makedirs(data_dir, exist_ok=True)
    with open(kev_snapshot_path(data_dir), "w", encoding="utf-8") as fh:
        json.dump(kev_index, fh, sort_keys=True)
        fh.write("\n")


# ---------------------------------------------------------------------------
# mode decision (§5 staleness guard)
# ---------------------------------------------------------------------------
def shards_present(data_dir):
    return bool(shards.list_shard_files(data_dir))


def decide_mode(requested, state, data_dir, oldest):
    if requested in ("full", "delta"):
        return requested
    if not shards_present(data_dir):
        return "full"
    last = state.get("last_processed_fetchTime")
    if not last:
        return "full"
    if oldest is None:
        return "full"            # empty/unreadable deltaLog window -> rebuild
    if last < oldest:
        return "full"            # window rolled past our cursor -> potential gap
    return "delta"


# ---------------------------------------------------------------------------
# FULL rebuild — accumulate per age band, flush on band boundary
# ---------------------------------------------------------------------------
def run_full(args, cfg, state, kev_index, change_rows):
    data_dir = args.data_dir
    shard_dir = os.path.join(data_dir, "shards")
    if os.path.isdir(shard_dir):
        for f in shards.list_shard_files(data_dir):
            os.remove(f)
    os.makedirs(shard_dir, exist_ok=True)

    created_clone = False
    clone_dir = args.clone_dir
    if not clone_dir:
        clone_dir = tempfile.mkdtemp(prefix="cvelist-")
        created_clone = True
    try:
        if created_clone or not os.path.isdir(os.path.join(clone_dir, "cves")):
            log(f"Cloning cvelistV5 (shallow) into {clone_dir} …")
            sources.shallow_clone(clone_dir)

        touched = set()
        counts = Counter()
        processed = 0
        limited = bool(args.limit)

        years = sorted(int(y) for y in sources.year_dirs(clone_dir))  # ascending
        cur_band = None
        band_rows: dict = {}

        def flush():
            if cur_band and band_rows:
                shards.write_shard(shards.shard_path(data_dir, cur_band), band_rows)
                touched.add(cur_band)

        for yi in years:
            band = shards.band_name_for(yi, cfg.band_uppers)
            if cur_band is not None and band != cur_band:
                flush()
                band_rows = {}
            cur_band = band
            ydir = os.path.join(clone_dir, "cves", str(yi))
            for root, _d, files in os.walk(ydir):
                for fn in files:
                    if not (fn.startswith("CVE-") and fn.endswith(".json")):
                        continue
                    rec = sources.load_record(os.path.join(root, fn))
                    if not parse.is_published(rec):
                        continue
                    row = parse.record_to_row(rec, kev_index, args.max_desc_chars)
                    band_rows[row["cve_id"]] = row
                    counts[yi] += 1
                    processed += 1
                    if limited and processed >= args.limit:
                        break
                if limited and processed >= args.limit:
                    break
            if limited and processed >= args.limit:
                break
        flush()
    finally:
        if created_clone and not args.keep_clone:
            shutil.rmtree(clone_dir, ignore_errors=True)

    summary = {"mode": "full", "added": processed, "updated": 0, "removed": 0}
    log(f"FULL rebuild: {processed:,} published rows across {len(counts)} years"
        + (" (LIMITED dry run)" if limited else ""))
    return summary, sorted(counts.items())


# ---------------------------------------------------------------------------
# DELTA update
# ---------------------------------------------------------------------------
def run_delta(args, cfg, state, kev_index, deltalog, session, change_rows):
    data_dir = args.data_dir
    now = _now_iso()
    last = state.get("last_processed_fetchTime")
    changed, errors = sources.changes_since(deltalog, last)
    if errors:
        log(f"deltaLog reported {len(errors)} error item(s) (informational); "
            f"sample: {errors[:2]}")
    if args.limit and len(changed) > args.limit:
        changed = dict(list(changed.items())[:args.limit])
    log(f"DELTA: {len(changed)} changed record(s) since {last!r}")

    records, fetch_errors = sources.fetch_records(
        session, changed, max_workers=args.max_workers)
    if fetch_errors:
        log(f"  ⚠ {len(fetch_errors)} record fetch error(s); "
            f"sample: {list(fetch_errors.items())[:2]}")

    cache = {}        # shard name -> rows_by_id
    touched = set()

    def get_rows(name):
        if name not in cache:
            cache[name] = shards.read_shard(shards.shard_path(data_dir, name))
        return cache[name]

    def shard_for(cid):
        try:
            return shards.shard_name_for(cid, cfg)
        except (ValueError, IndexError):
            return None

    added = updated = removed = 0
    processed = set()

    for cid, rec in records.items():
        name = shard_for(cid)
        if name is None:
            continue
        rows = get_rows(name)
        touched.add(name)
        existed = cid in rows
        if parse.is_published(rec):
            row = parse.record_to_row(rec, kev_index, args.max_desc_chars)
            shards.upsert(rows, row)
            ctype = "updated" if existed else "added"
            added += ctype == "added"
            updated += ctype == "updated"
            change_rows.append({"cve_id": cid, "change_type": ctype,
                                "date_updated": row["date_updated"],
                                "shard": name, "run_utc": now})
        elif existed:
            shards.remove(rows, cid)
            removed += 1
            change_rows.append({"cve_id": cid, "change_type": "removed",
                                "date_updated": "", "shard": name, "run_utc": now})
        processed.add(cid)

    # KEV-only changes: refresh rows whose KEV status moved even if the record
    # itself didn't change this window.
    prev_kev = load_kev_snapshot(data_dir)
    kev_changed = {cid for cid in set(prev_kev) | set(kev_index)
                   if prev_kev.get(cid) != kev_index.get(cid)}
    if args.limit:
        kev_changed = set()  # a limited/dry run must not fan out across all of KEV
    kev_updates = 0
    for cid in kev_changed:
        if cid in processed or not _CVE_RE.match(cid):
            continue
        name = shard_for(cid)
        if name is None:
            continue
        path = shards.shard_path(data_dir, name)
        if name not in cache and not os.path.exists(path):
            continue  # we don't carry this CVE (e.g. not PUBLISHED) — skip
        rows = get_rows(name)
        if cid in rows:
            rows[cid].update(parse.kev_fields(cid, kev_index))
            touched.add(name)
            updated += 1
            kev_updates += 1
            change_rows.append({"cve_id": cid, "change_type": "updated",
                                "date_updated": rows[cid]["date_updated"],
                                "shard": name, "run_utc": now})
    if kev_updates:
        log(f"  KEV-only refresh touched {kev_updates} existing row(s)")

    for name in touched:
        shards.write_shard(shards.shard_path(data_dir, name), cache[name])

    save_kev_snapshot(data_dir, kev_index)
    summary = {"mode": "delta", "added": added, "updated": updated,
               "removed": removed}
    log(f"DELTA done: +{added} added, ~{updated} updated, -{removed} removed")
    return summary, None


# ---------------------------------------------------------------------------
# finalize: stats, change files, README, state
# ---------------------------------------------------------------------------
def write_changes_csv(data_dir, today, change_rows, max_rows):
    path = os.path.join(data_dir, "changes", f"changes_{today}.csv")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    suppressed = len(change_rows) > max_rows
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CHANGE_COLUMNS, lineterminator="\n")
        w.writeheader()
        if not suppressed:
            for r in sorted(change_rows, key=lambda r: shards.sort_key(r["cve_id"])):
                w.writerow(r)
    return path, suppressed


def append_changelog(data_dir, today, summary, total_rows, suppressed):
    path = os.path.join(data_dir, "changes", "CHANGELOG.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    new = not os.path.exists(path)
    note = " (per-row log suppressed)" if suppressed else ""
    line = (f"- {today} · **{summary['mode']}** · "
            f"+{summary['added']} / ~{summary['updated']} / -{summary['removed']} · "
            f"{total_rows:,} total rows{note}\n")
    with open(path, "a", encoding="utf-8") as fh:
        if new:
            fh.write("# Change log\n\n"
                     "One line per run: date · mode · added / updated / removed · total.\n\n")
        fh.write(line)


def collect_shard_stats(data_dir):
    rows_total = 0
    table = []
    for path in shards.list_shard_files(data_dir):
        name = os.path.splitext(os.path.basename(path))[0]
        s = shards.stats_from_file(path)
        rows_total += s["rows"]
        table.append((name, s))
    return rows_total, table


def render_stats_md(total_rows, table):
    lines = [
        f"**Total rows:** {total_rows:,}  ·  **Shards:** {len(table)}  "
        f"·  generated {_now_iso()}",
        "",
        "| shard | rows | size | years |",
        "| --- | ---: | ---: | :---: |",
    ]
    for name, s in sorted(table):
        mb = s["bytes"] / (1024 * 1024)
        span = (f"{s['year_min']}" if s["year_min"] == s["year_max"]
                else f"{s['year_min']}–{s['year_max']}") if s["year_min"] else "—"
        lines.append(f"| `{name}` | {s['rows']:,} | {mb:.2f} MB | {span} |")
    return "\n".join(lines)


def update_readme_stats(readme_path, total_rows, table):
    block = f"{README_START}\n{render_stats_md(total_rows, table)}\n{README_END}"
    if not os.path.exists(readme_path):
        return
    text = open(readme_path, encoding="utf-8").read()
    if README_START in text and README_END in text:
        text = re.sub(re.escape(README_START) + r".*?" + re.escape(README_END),
                      block, text, flags=re.DOTALL)
    else:
        text = text.rstrip() + "\n\n## Dataset statistics\n\n" + block + "\n"
    with open(readme_path, "w", encoding="utf-8") as fh:
        fh.write(text)


def print_size_table(total_rows, table, year_counts=None):
    log("")
    log(f"{'shard':24} {'rows':>9} {'MB':>9}  years")
    log("-" * 56)
    for name, s in sorted(table):
        mb = s["bytes"] / (1024 * 1024)
        span = "—" if s["year_min"] is None else (
            f"{s['year_min']}" if s["year_min"] == s["year_max"]
            else f"{s['year_min']}-{s['year_max']}")
        log(f"{name:24} {s['rows']:>9,} {mb:>9.2f}  {span}")
    log("-" * 56)
    log(f"{'TOTAL':24} {total_rows:>9,}")
    if year_counts:
        log("\nper-year published counts (this build):")
        for year, n in sorted(year_counts):
            log(f"  {year}: {n:,}")


def finalize(args, cfg, state, mode, summary, newest, kev_date,
             change_rows, year_counts):
    data_dir = args.data_dir
    today = _today()
    total_rows, table = collect_shard_stats(data_dir)

    for name, s in sorted(table):
        if s["bytes"] > cfg.shard_max_bytes:
            log(f"  ⚠ shard {name} is {s['bytes']:,} bytes (> {cfg.shard_max_bytes:,}); "
                f"approaching GitHub's 100 MB limit — lower a --band-uppers boundary "
                f"to peel the oldest years into their own shard")

    changes_path, suppressed = write_changes_csv(
        data_dir, today, change_rows, args.max_change_rows)
    append_changelog(data_dir, today, summary, total_rows, suppressed)
    update_readme_stats(args.readme, total_rows, table)

    state["schema_version"] = state_mod.SCHEMA_VERSION
    state["last_run_utc"] = _now_iso()
    state["run_mode_last"] = mode
    state["total_rows"] = total_rows
    state["kev_catalog_date"] = kev_date
    state["shards"] = {name: s for name, s in table}
    if not args.limit and newest:
        state["last_processed_fetchTime"] = newest
    elif args.limit:
        log("note: --limit set, NOT advancing last_processed_fetchTime "
            "(this is a partial build)")
    state_mod.save_state(data_dir, state)

    print_size_table(total_rows, table, year_counts)
    log(f"\nchange log: {changes_path}"
        + (" (header only — suppressed)" if suppressed else f" ({len(change_rows)} rows)"))
    log(f"state: {state_mod.state_path(data_dir)}")
    log("no git performed (build.py never commits; --no-commit honored).")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_band_uppers(text):
    out = []
    for piece in str(text).split(","):
        piece = piece.strip()
        if piece:
            out.append(int(piece))
    return out or list(shards.DEFAULT_BAND_UPPERS)


def build_arg_parser():
    p = argparse.ArgumentParser(prog="src.build",
                                description="Build/refresh the sharded CVE CSV dataset.")
    p.add_argument("--mode", choices=["auto", "full", "delta"], default="auto")
    p.add_argument("--data-dir", default="data")
    p.add_argument("--readme", default="README.md")
    p.add_argument("--limit", type=int, default=0,
                   help="cap records processed (dry runs); 0 = no cap")
    p.add_argument("--max-desc-chars", type=int, default=0,
                   help="truncate description_en to N chars (0 = no truncation)")
    p.add_argument("--band-uppers", default="2022,2025",
                   help="comma-separated ascending year upper-bounds defining the "
                        "age-band shards (default 2022,2025 -> 3 shards)")
    p.add_argument("--shard-max-bytes", type=int,
                   default=shards.DEFAULT_SHARD_MAX_BYTES)
    p.add_argument("--max-change-rows", type=int, default=50000,
                   help="above this, the per-row change CSV is suppressed to a header")
    p.add_argument("--max-workers", type=int, default=12)
    p.add_argument("--clone-dir", default=None,
                   help="reuse an existing clone/extract dir instead of cloning")
    p.add_argument("--keep-clone", action="store_true")
    p.add_argument("--no-commit", action="store_true",
                   help="accepted for the documented dry run; build never commits")
    p.add_argument("--no-kev", action="store_true",
                   help="skip the KEV fetch (offline/testing)")
    return p


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    os.makedirs(os.path.join(args.data_dir, "shards"), exist_ok=True)
    os.makedirs(os.path.join(args.data_dir, "changes"), exist_ok=True)

    state = state_mod.load_state(args.data_dir)
    cfg = ShardConfig(band_uppers=_parse_band_uppers(args.band_uppers),
                      shard_max_bytes=args.shard_max_bytes)

    session = sources.make_session()

    kev_index, kev_date = ({}, state.get("kev_catalog_date"))
    if not args.no_kev:
        log("Fetching CISA KEV catalog …")
        kev_index, kev_date = sources.fetch_kev(session)
        log(f"  KEV entries: {len(kev_index):,} (catalog {kev_date})")

    log("Fetching deltaLog.json …")
    deltalog = sources.fetch_delta_log(session)
    oldest, newest = sources.deltalog_bounds(deltalog)
    log(f"  deltaLog window: {oldest} … {newest} ({len(deltalog)} fetches)")

    mode = decide_mode(args.mode, state, args.data_dir, oldest)
    log(f"mode = {mode} (requested {args.mode}); bands = {cfg.band_uppers}")

    change_rows = []
    if mode == "full":
        summary, year_counts = run_full(args, cfg, state, kev_index, change_rows)
        if not args.no_kev:
            save_kev_snapshot(args.data_dir, kev_index)
    else:
        summary, year_counts = run_delta(
            args, cfg, state, kev_index, deltalog, session, change_rows)

    finalize(args, cfg, state, mode, summary, newest, kev_date,
             change_rows, year_counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
