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
_Snapshot from the initial validation build (2026-06-20, 27-column schema); the
daily workflow regenerates this block on every run._

**Total rows:** 341,897  ·  **Shards:** 10  ·  **Total size:** ~203 MB

| shard | rows | size | years |
| --- | ---: | ---: | :---: |
| `cve_archive_le2017` | 102,915 | 41.38 MB | 1999–2017 |
| `cve_2018` | 16,188 | 7.70 MB | 2018 |
| `cve_2019` | 16,092 | 8.48 MB | 2019 |
| `cve_2020` | 19,381 | 10.89 MB | 2020 |
| `cve_2021` | 22,584 | 14.35 MB | 2021 |
| `cve_2022` | 26,421 | 17.71 MB | 2022 |
| `cve_2023` | 30,590 | 22.03 MB | 2023 |
| `cve_2024` | 38,380 | 32.33 MB | 2024 |
| `cve_2025` | 43,010 | 34.49 MB | 2025 |
| `cve_2026` | 26,336 | 23.23 MB | 2026 (partial) |

> The largest shard is 34 MB and the archive is 41 MB — comfortable headroom
> under the 90 MB cap, so the 2017 cutoff is safe. Trimming the schema from 35 to
> 27 columns cut the archive nearly in half (it was 80 MB at 35 columns).
<!-- STATS:END -->

## Schema

Exactly one row per CVE, 27 columns, in this order. Multi-valued fields are
flattened into one cell with ` | ` as the delimiter, de-duplicated and
order-stable; all internal newlines and tabs are collapsed to single spaces.
Files are UTF-8, `QUOTE_MINIMAL`, with `\n` line endings.

| # | column | meaning |
|---:|---|---|
| 1 | `cve_id` | the CVE ID (year and bucket are derivable from it) |
| 2 | `assigner_short_name` | assigning CNA short name |
| 3 | `date_reserved` | ISO-8601, as provided |
| 4 | `date_published` | ISO-8601, as provided |
| 5 | `date_updated` | ISO-8601, as provided |
| 6 | `title` | CNA title if present, else empty |
| 7 | `description_en` | English descriptions (lang starts with `en`), concatenated, whitespace collapsed |
| 8 | `cvss_version` | e.g. `3.1` |
| 9 | `cvss_base_score` | numeric, as stored (a JSON `10` stays `10`) |
| 10 | `cvss_base_severity` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` (`NONE` at 0.0); derived from score if the record omits it |
| 11 | `cvss_vector` | CVSS vector string |
| 12 | `cvss_source` | `cna` or `cisa-adp` (which container the score came from) |
| 13 | `cwe_id` | primary CWE, e.g. `CWE-362` |
| 14 | `cwe_name` | the CWE description string if present |
| 15 | `cwe_source` | `cna` or `cisa-adp` |
| 16 | `cwe_ids_all` | every distinct `CWE-####` found in any container, `|`-joined |
| 17 | `cisa_kev` | `true`/`false` — from the CISA KEV catalog, matched by CVE ID |
| 18 | `kev_date_added` | KEV `dateAdded` when listed |
| 19 | `kev_known_ransomware` | KEV `knownRansomwareCampaignUse` when listed |
| 20 | `ssvc_exploitation` | CISA-ADP SSVC `Exploitation` |
| 21 | `ssvc_automatable` | CISA-ADP SSVC `Automatable` |
| 22 | `ssvc_technical_impact` | CISA-ADP SSVC `Technical Impact` |
| 23 | `vendors` | distinct vendors from the CNA `affected[]`, `|`-joined |
| 24 | `products` | distinct products from the CNA `affected[]`, `|`-joined |
| 25 | `affected_count` | number of CNA `affected[]` entries |
| 26 | `cpes` | distinct CPE 2.3 criteria (from `affected[].cpes` and `cpeApplicability`), capped at 50 with a trailing `…(+N)` |
| 27 | `reference_count` | distinct reference count across CNA + ADP, after dropping x_transferred duplicates |

### Severity and weakness precedence

For both CVSS and the primary CWE: prefer the CNA container; only if the CNA has
none, fall back to CISA-ADP. Within the chosen container, take the highest CVSS
version (`v4.0 > v3.1 > v3.0 > v2.0`). `cvss_source` / `cwe_source` records which
container won. A record may carry no CVSS at all (common for Linux-kernel CVEs);
those score fields are left empty rather than invented. In practice CISA-ADP only
backfills a CVSS when the CNA omitted one, so the two rarely conflict.

### KEV is authoritative from the CISA feed

`cisa_kev` and the `kev_*` columns come from CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
fetched once per run and matched by CVE ID — more reliable than scraping KEV out
of the ADP container. Because KEV is fetched every run, a CVE's KEV status stays
current even on a day its own record didn't change.

### What's deliberately not a column

- **Trimmed for space (8 columns removed from the original 35):** `state` (always
  PUBLISHED), `year` / `source_path` (derivable from `cve_id`), `assigner_org_id`
  (the short name is the human-usable one), `data_version`, `has_cisa_adp`,
  `record_dateUpdated_hash` (an internal change-key), and `reference_urls` — the
  single fattest, lowest-value column (up to 50 links jammed into one cell;
  `reference_count` keeps the "how documented is it" signal and `cve_id`
  reconstructs the link to the full record). Dropping these cut the dataset ~34%.
- **Never stored:** per-version ranges, git commit hashes, and `programFiles` —
  Linux-kernel CVEs carry dozens of version ranges and enumerating them would
  explode the row. Reference/CPE lists are capped at 50. Only English
  descriptions are kept; full kernel descriptions (which embed stack traces) are
  the main driver of file size, so `--max-desc-chars` can truncate them.

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
`--shard-max-bytes`). The archive shard itself is the one the splitter can't break
up; if it ever nears 90 MB, **lower** `--archive-cutoff-year` so the oldest years
move into their own shards (at the current 41 MB it has plenty of headroom).

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
A full build of the current dataset is ~342k rows / ~203 MB and runs in ~60 s.

## First full build

The very first run must be a **full** build and produces a large initial commit.
Trigger it manually: go to **Actions → Daily CVE refresh → Run workflow** and pick
`mode = full`. After that the daily 07:00 UTC schedule keeps it current with small
incremental commits, rebuilding fully on its own only if the deltaLog window ever
rolls past the saved cursor.
