# nvd-csv — a daily, sharded CSV of every published CVE

This repo is both the code and the dataset. A GitHub Actions workflow runs once
a day, pulls the latest data from the official
[CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) repository, and
commits a refreshed set of CSV shards back here — one row per **PUBLISHED** CVE,
all years.

Daily updates are incremental, driven by the upstream `cves/deltaLog.json`, and
fall back to a full rebuild automatically when the incremental window can't be
trusted (see [Incremental logic](#incremental-logic-and-the-staleness-guard)).

- **Data lives in** [`data/shards/`](data/shards) — `cve_archive_le2017.csv`,
  `cve_2018.csv`, … one file per recent year.
- **Run state** is [`data/state.json`](data/state.json); per-run change logs are
  in [`data/changes/`](data/changes).
- **Scope:** PUBLISHED only. REJECTED and RESERVED records are excluded, and a
  CVE that transitions out of PUBLISHED is deleted from its shard and logged as
  a removal.

## Dataset statistics

<!-- STATS:START -->
**Total rows:** 341,899  ·  **Shards:** 10  ·  generated 2026-06-20T02:07:48+00:00

| shard | rows | size | years |
| --- | ---: | ---: | :---: |
| `cve_2018` | 16,188 | 6.67 MB | 2018 |
| `cve_2019` | 16,092 | 7.25 MB | 2019 |
| `cve_2020` | 19,381 | 9.04 MB | 2020 |
| `cve_2021` | 22,584 | 11.53 MB | 2021 |
| `cve_2022` | 26,421 | 14.21 MB | 2022 |
| `cve_2023` | 30,590 | 17.14 MB | 2023 |
| `cve_2024` | 38,380 | 24.19 MB | 2024 |
| `cve_2025` | 43,010 | 27.35 MB | 2025 |
| `cve_2026` | 26,338 | 18.83 MB | 2026 |
| `cve_archive_le2017` | 102,915 | 35.80 MB | 1999–2017 |
<!-- STATS:END -->

## Schema

Exactly one row per CVE, 18 columns, in this order. Multi-valued fields are
flattened into one cell with ` | ` as the delimiter, de-duplicated and
order-stable; all internal newlines and tabs are collapsed to single spaces.
Files are UTF-8, `QUOTE_MINIMAL`, with `\n` line endings.

| # | column | meaning |
|---:|---|---|
| 1 | `cve_id` | the CVE ID (year and bucket are derivable from it) |
| 2 | `assigner_short_name` | assigning CNA short name |
| 3 | `date_published` | ISO-8601, as provided |
| 4 | `date_updated` | ISO-8601, as provided |
| 5 | `title` | CNA title if present, else empty |
| 6 | `description_en` | English descriptions (lang starts with `en`), concatenated, whitespace collapsed |
| 7 | `cvss_version` | e.g. `3.1` |
| 8 | `cvss_base_score` | numeric, as stored (the qualitative severity band is derivable from this) |
| 9 | `cvss_vector` | CVSS vector string |
| 10 | `cvss_source` | `cna` or `cisa-adp` (which container the score came from) |
| 11 | `cwe_ids_all` | every distinct `CWE-####` found in any container, `|`-joined |
| 12 | `cisa_kev` | `true`/`false` — from the CISA KEV catalog, matched by CVE ID |
| 13 | `kev_date_added` | KEV `dateAdded` when listed |
| 14 | `ssvc_exploitation` | CISA-ADP SSVC `Exploitation` |
| 15 | `ssvc_automatable` | CISA-ADP SSVC `Automatable` |
| 16 | `ssvc_technical_impact` | CISA-ADP SSVC `Technical Impact` |
| 17 | `vendors` | distinct vendors from the CNA `affected[]`, `|`-joined |
| 18 | `products` | distinct products from the CNA `affected[]`, `|`-joined |

### CVSS precedence and CWE aggregation

For CVSS: prefer the CNA container; only if the CNA has none, fall back to
CISA-ADP. Within the chosen container, take the highest version
(`v4.0 > v3.1 > v3.0 > v2.0`); `cvss_source` records which container won. A
record may carry no CVSS at all (common for Linux-kernel CVEs); those fields are
left empty rather than invented. In practice CISA-ADP only backfills a CVSS when
the CNA omitted one, so the two rarely conflict. The qualitative severity band is
omitted because it's derivable from `cvss_base_score`. `cwe_ids_all` collects
every distinct CWE id found in any container (CNA + ADP).

### KEV is authoritative from the CISA feed

`cisa_kev` / `kev_date_added` come from CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
fetched once per run and matched by CVE ID — more reliable than scraping KEV out
of the ADP container. Because KEV is fetched every run, a CVE's KEV status stays
current even on a day its own record didn't change.

### What's deliberately not a column

The schema is intentionally lean. Dropped as constant, derivable, or
low-value-per-byte: `state` (always PUBLISHED), `year` / `source_path`
(derivable from `cve_id`), `assigner_org_id`, `data_version`, `has_cisa_adp`,
`record_dateUpdated_hash`, `date_reserved`, `cvss_base_severity` (derivable from
the score), the primary `cwe_id`/`cwe_name`/`cwe_source` (superseded by
`cwe_ids_all`), `kev_known_ransomware`, `affected_count`, `cpes`,
`reference_count`, and `reference_urls`. Never stored at all: per-version ranges,
git commit hashes, and `programFiles` (Linux-kernel CVEs carry dozens of version
ranges and enumerating them would explode the row). Only English descriptions are
kept; full kernel descriptions (which embed stack traces) drive file size, so
`--max-desc-chars` can truncate them.

## Sharding strategy

Most records and nearly all daily churn are in recent years; old years are large
in span but small and static. So shards are by age, not strict calendar:

- one **archive** shard for all years `<= ARCHIVE_CUTOFF_YEAR` (default **2017**):
  `data/shards/cve_archive_le2017.csv`
- one shard **per year** after that: `cve_2018.csv` … `cve_<currentYear>.csv`

This keeps every committed file well under GitHub's 100 MB limit and keeps each
daily commit small — only the shards that actually changed are rewritten. Shards
are written with rows sorted by `(year, sequence)`, so the same set of rows always
produces identical bytes (the backbone of the idempotency guarantee).

**Self-tuning safety:** every run records each shard's row count and byte size
into `state.json` and the stats block above, and warns loudly about any shard over
`SHARD_MAX_BYTES` (default **90 MB**). A per-year shard that would exceed the cap
is auto-split into CVE-ID thousand buckets (`cve_2025_0xxx.csv`,
`cve_2025_1xxx.csv`, …) and the year is recorded in `state.json["split_years"]`.
The cutoff and threshold are CLI-tunable in one place (`--archive-cutoff-year`,
`--shard-max-bytes`). The archive shard is the one the splitter can't break up; if
it ever nears 90 MB, **lower** `--archive-cutoff-year` so the oldest years move
into their own shards (see the stats block above for current sizes).

## Incremental logic and the staleness guard

State persists in `data/state.json` (`last_processed_fetchTime` = the newest
deltaLog `fetchTime` already incorporated). Each run:

1. **Decide mode.** Fetch `cves/deltaLog.json`, read the *actual* oldest and
   newest `fetchTime` present (the upstream retention is size-capped and has been
   cut from ~30 to ~15 days during high-volume periods, so the window is never
   assumed). Go **FULL** when state/shards are missing, when the cursor is null,
   or when the cursor is older than the oldest `fetchTime` (the window rolled past
   us → possible gap). Otherwise **DELTA**. `--mode auto|full|delta` overrides.
2. **DELTA:** union every `new[]`+`updated[]` entry newer than the cursor, fetch
   just those raw records concurrently (≤12 workers, retry + backoff), upsert by
   `cve_id` into the right shard, delete any that are no longer PUBLISHED, refresh
   KEV-only changes onto existing rows, then advance the cursor to the newest
   `fetchTime`.
3. **FULL:** acquire the whole dataset (shallow `git clone --depth 1`), rebuild
   every shard from scratch, then advance the cursor.
4. Write outputs, update `state.json`, write the daily change log, regenerate the
   stats block, and (in CI) commit only if something changed.

**Idempotency:** upserts are keyed solely on `cve_id`, and shard bytes are
deterministic, so re-running a delta changes nothing.

## Repo layout

```
src/        build.py (CLI/orchestration) · parse.py (record→row) · shards.py
            (naming/IO/split) · sources.py (deltaLog/raw/KEV/clone) · state.py
tests/      fixtures/ (real + synthetic CVE records) · test_parse · test_shards · test_build
data/       shards/ · changes/ · state.json · kev_snapshot.json  (generated, committed)
.github/workflows/daily-update.yml
```

## Run it locally

```bash
pip install -r requirements.txt          # runtime: requests only
# dry run on a subset (clones upstream, builds the 2000 newest, commits nothing):
python -m src.build --mode full --limit 2000 --no-commit

# real full build into a scratch dir (does not touch the committed data/):
python -m src.build --mode full --data-dir /tmp/full-data --readme /tmp/r.md

# tests (dev deps add pytest + pandas for the CSV round-trip parity check):
pip install -r requirements-dev.txt && python -m pytest -q
```

`build.py` never runs git — committing is the workflow's job, so a local run only
writes files. `--no-commit` is accepted so the documented dry run works verbatim.
A full build of the current dataset is ~342k rows and runs in about a minute.

## First full build

The very first run must be a **full** build and produces a large initial commit.
Trigger it manually: go to **Actions → Daily CVE refresh → Run workflow** and pick
`mode = full`. After that the daily 07:00 UTC schedule keeps it current with small
incremental commits, rebuilding fully on its own only if the deltaLog window ever
rolls past the saved cursor.
