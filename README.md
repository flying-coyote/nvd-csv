# nvd-csv — every published CVE as a CSV you can actually open

Every publicly known software vulnerability gets a **CVE** ID (Common
Vulnerabilities and Exposures, the industry's universal name for a specific
flaw, like `CVE-2021-44228` for Log4Shell). The official record for each one is
published as JSON, and there are roughly **340,000** of them. This repo turns
that pile into a handful of plain CSV files — one row per CVE — and refreshes
them every day so you can open the whole history of disclosed vulnerabilities in
Excel, pandas, or DuckDB without writing a single API call.

If you're learning vulnerability management or detection engineering, this is
meant to be a low-friction place to start poking at real data.

## Why this exists

The authoritative vulnerability data is free, but it's awkward to get at if you
just want to look around:

- The CVE Program publishes every record as an individual JSON file in one giant
  git repository, [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5).
  Cloning it is several gigabytes and ~360,000 files, and each file follows the
  nested [CVE JSON 5.x schema](https://github.com/CVEProject/cve-schema) where
  the interesting fields (severity, weakness, affected products) live in
  different places depending on who filled them in.
- The [National Vulnerability Database (NVD)](https://nvd.nist.gov) — NIST's
  enriched view of the same CVEs — has a JSON API, but it's rate-limited, it
  paginates, and it sometimes lags behind the source.

So a simple question like *"show me every actively-exploited CVE with a critical
CVSS score that was published in 2024"* normally means cloning gigabytes,
learning the JSON shape, reconciling two different data publishers inside each
record, de-duplicating, and only then filtering. This repo does that work once a
day and hands you the answer-ready table instead. No API key, no rate limits, no
JSON parsing — just `read_csv`.

## The vocabulary (what the columns are talking about)

A CVE record is assembled by a few different organizations, and a few standards
bodies score and classify it. You'll see all of these in the columns:

- **CNA — CVE Numbering Authority.** The organization that assigned the ID and
  wrote the base record (a vendor like Microsoft, a project like the Linux
  kernel, or a coordinator like MITRE). It's in `assigner_short_name`.
- **CVSS — [Common Vulnerability Scoring System](https://www.first.org/cvss/).**
  A 0.0–10.0 severity score plus a "vector" string describing how the attack
  works. Columns `cvss_version`, `cvss_base_score`, `cvss_vector`.
- **CWE — [Common Weakness Enumeration](https://cwe.mitre.org).** The *type* of
  flaw, as a catalog ID — e.g. `CWE-79` is cross-site scripting, `CWE-416` is a
  use-after-free. Column `cwe_ids_all`. Look any ID up at
  [cwe.mitre.org](https://cwe.mitre.org).
- **CPE — [Common Platform Enumeration](https://nvd.nist.gov/products/cpe).** A
  structured identifier for an affected product and version, like
  `cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*`. It's what scanners and asset
  inventories match against. Column `cpes`.
- **KEV — [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).**
  The short list of CVEs that are known to be exploited in the wild — in other
  words, the "patch these first" list. Columns `cisa_kev`, `kev_date_added`.
- **SSVC — [Stakeholder-Specific Vulnerability Categorization](https://www.cisa.gov/ssvc).**
  CISA's prioritization signals: is it being exploited, can it be automated, how
  bad is the impact. Columns `ssvc_exploitation`, `ssvc_automatable`,
  `ssvc_technical_impact`.
- **ADP / Vulnrichment.** Many records arrive from the CNA without a score or a
  CPE, so CISA's [Vulnrichment](https://github.com/cisagov/vulnrichment) program
  back-fills the CVSS, CWE, CPE, and SSVC. Where a value came from the CNA versus
  this enrichment is recorded in `cvss_source` (`cna` or `cisa-adp`).

## Dataset statistics

<!-- STATS:START -->
**Total rows:** 342,034  ·  **Shards:** 3  ·  generated 2026-06-22T12:47:20+00:00

| shard | rows | size | years |
| --- | ---: | ---: | :---: |
| `cve_2022_and_before` | 203,584 | 80.10 MB | 1999–2022 |
| `cve_2023_to_2025` | 111,992 | 71.11 MB | 2023–2025 |
| `cve_2026_to_now` | 26,458 | 18.99 MB | 2026 |
<!-- STATS:END -->

## What's in each row

One row per CVE, 19 columns. Everything is text (it's CSV), so cast scores and
the KEV flag to numbers before you compare them. Multi-valued fields (several
products, several CWEs) are packed into one cell separated by ` | `.

| group | columns | what it tells you |
|---|---|---|
| **identity** | `cve_id`, `assigner_short_name` | which CVE, and who wrote it |
| **timing** | `date_published`, `date_updated` | when it went public and when it last changed (calendar dates, UTC; `date_updated` is blank if unchanged since publish) |
| **description** | `title`, `description_en` | the human-readable summary of the flaw |
| **how bad** | `cvss_version`, `cvss_base_score`, `cvss_vector`, `cvss_source` | the severity score, the vector, and where the score came from |
| **what kind** | `cwe_ids_all` | the weakness type(s), e.g. `CWE-787 \| CWE-125` |
| **being exploited?** | `cisa_kev`, `kev_date_added`, `ssvc_exploitation`, `ssvc_automatable`, `ssvc_technical_impact` | is it on the KEV list (`1`/`0`), and CISA's SSVC triage |
| **what it affects** | `vendors`, `products`, `cpes` | affected vendor/product names, plus machine-matchable CPE 2.3 strings |

A note on severity: there's no `cvss_base_severity` column because the word
(LOW/MEDIUM/HIGH/CRITICAL) is just a band of the number — 0.1–3.9 is Low,
4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical — so you derive it from
`cvss_base_score`.

A note on `date_updated`: it's the last time a publisher (the CNA, or CISA via
Vulnrichment) actually changed the record, read from the record's own provider
metadata rather than the CVE Program's `cveMetadata.dateUpdated` — which a 2024
bulk migration stamped onto ~46% of records, burying their real dates. It's left
**blank** when the record hasn't changed since publication.

## Reading the scoring and exploitation fields

These three are where most of the prioritization signal lives, so they're worth
understanding rather than skimming past.

**`cvss_vector` — how the attack works, in shorthand.** A vector like
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (that's Log4Shell) is a
slash-separated list of the metrics that produced the score. The ones worth
reading at a glance:

- **AV — Attack Vector:** where the attacker has to be. `N`etwork (reachable over
  the internet — the dangerous one), `A`djacent (same local network), `L`ocal
  (needs local access), `P`hysical.
- **AC — Attack Complexity:** `L`ow or `H`igh — how much has to line up for it
  to work.
- **PR — Privileges Required:** `N`one / `L`ow / `H`igh — does the attacker need
  an account first.
- **UI — User Interaction:** `N`one or `R`equired — does a victim have to click
  something.
- **C / I / A — impact** to Confidentiality, Integrity, Availability, each
  `H`igh / `L`ow / `N`one.

The thing to watch for is `AV:N/AC:L/PR:N/UI:N` with high C/I/A — remotely
reachable, easy, no login, no click, total compromise. That combination is why
Log4Shell is a 10.0. You don't have to decode it by hand: paste the whole vector
into the
[FIRST CVSS calculator](https://www.first.org/cvss/calculator/3.1) to see it
expanded, and read the full
[CVSS v3.1 spec](https://www.first.org/cvss/v3.1/specification-document) (or
[v4.0](https://www.first.org/cvss/v4-0/), which adds more letters but works the
same way) for what each metric means.

**SSVC — CISA's "what should I do about it" triage.** Three decision points,
straight from the record:

| column | values |
|---|---|
| `ssvc_exploitation` | `none` · `poc` (proof-of-concept exists) · `active` (in the wild) |
| `ssvc_automatable` | `yes` · `no` (can an attacker automate it at scale) |
| `ssvc_technical_impact` | `partial` · `total` (how much control it gives) |

Read together they tell you how hard to run: `active` + `yes` + `total` is a
drop-everything bug. Background and the full decision tree are in
[CISA's SSVC guide](https://www.cisa.gov/ssvc). (Empty means the record hasn't
been triaged — most non-enriched CVEs.)

**KEV — the authoritative "exploited in the wild" list.** `cisa_kev = 1` means
the CVE is on
[CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
and `kev_date_added` is when CISA added it. US federal civilian agencies are
legally required to remediate KEV entries by a deadline, which is why it's the
de-facto "patch this first, argue later" list for everyone. It's small (~1,600
of the 340k) and high-signal — a good first filter.

## How to use it

Clone the repo (or download the three CSVs) and point any tool at
`data/shards/*.csv`. They share the same columns, so reading all three together
gives you the full dataset.

**[DuckDB](https://duckdb.org)** is the easiest because it reads the CSVs
directly and globs all three at once:

```sql
-- Every actively-exploited, critical-severity CVE from 2024, newest first
SELECT cve_id, cvss_base_score, products, description_en
FROM 'data/shards/*.csv'
WHERE cisa_kev = '1'
  AND TRY_CAST(cvss_base_score AS DOUBLE) >= 9.0
  AND date_published >= '2024-01-01'
ORDER BY date_published DESC;
```

**pandas:**

```python
import glob, pandas as pd
df = pd.concat(pd.read_csv(f, dtype=str) for f in glob.glob("data/shards/*.csv"))

# all use-after-free bugs (CWE-416) in the Linux kernel
kernel_uaf = df[df["cwe_ids_all"].str.contains("CWE-416", na=False)
               & df["vendors"].str.contains("Linux", na=False)]

# things on CISA's KEV list, sorted by when they were added
kev = df[df["cisa_kev"] == "1"].sort_values("kev_date_added")
```

A few questions a junior analyst can answer in one line with this data: which
CVEs are *known to be exploited* right now (`cisa_kev = '1'`); what the most
common weakness types are this year (group by `cwe_ids_all`); every vulnerability
in a product you run (filter `products` or `cpes`); how a specific CVE was scored
and by whom (`cvss_base_score` + `cvss_source`). For Excel, see the next section.

## Live data in Excel (Power Query)

[`excel/merge-shards.pq`](excel/merge-shards.pq) is a Power Query (M) script that
pulls the three shards straight from this repo and stacks them into one table you
can refresh on demand. On Windows Excel:

1. **Data → Get Data → From Other Sources → Blank Query**
2. **Home → Advanced Editor**, clear it, and paste the contents of
   `excel/merge-shards.pq`
3. **Done → Close & Load** — you get a worksheet table of every CVE, with the
   score, KEV flag, and dates already typed.
4. **Data → Refresh All** any time to pull the latest daily build.

(Mac Excel doesn't have Power Query — use the DuckDB or pandas snippets above.)

## How fresh it is, and how to see what changed

A GitHub Actions workflow runs every day at 07:00 UTC. Most days it only fetches
the handful of records that changed upstream (it follows the CVE Program's own
`deltaLog.json` change feed) and commits a small update; the daily diff in
`data/changes/` tells you exactly which CVEs were added, updated, or removed. The
KEV list is re-checked every run, so a CVE's `cisa_kev` flag flips from `0` to
`1` the day CISA adds it, even if the vulnerability record itself didn't change.
If the change feed ever rolls past where we left off, the build rebuilds the
whole dataset from scratch automatically, so it's self-healing.

## What's deliberately left out — and where to get it

To keep the files small and readable, the schema is trimmed to what's useful at a
glance. If you need more, the full record is always one click away at
`https://www.cve.org/CVERecord?id=<CVE-ID>` or in the
[cvelistV5](https://github.com/CVEProject/cvelistV5) JSON.

- **Reference links** aren't a column — a record can have 50 advisory/patch/PoC
  URLs, which doesn't belong in a CSV cell. Go to the CVE record for those.
- **Per-version ranges and git commit hashes** aren't kept — kernel CVEs alone
  can list dozens, and they'd swamp the row. `cpes` carries version info where
  it's available.
- **Several fields are dropped because they're derivable or redundant:** the
  CVSS severity word (from the score), the CWE *name* (look the `CWE-####` up at
  [cwe.mitre.org](https://cwe.mitre.org)), the year (from the `cve_id`), and a
  few plumbing fields. `cpes` was *kept* on purpose: it's the only
  machine-matchable product identifier, and only ~14% of CVEs carry one, so it
  can't be reconstructed from `vendors`/`products`.

## How the files are organized

The data is split into three CSVs by age (`cve_2022_and_before`,
`cve_2023_to_2025`, `cve_2026_to_now`) only because GitHub caps a single file
at 100 MB and the full dataset is ~180 MB. There's nothing clever to it — read
all three and you have everything. The split points are tunable
(`--band-uppers`) if you rebuild it yourself, and the build warns if any file
creeps toward the cap.

## Caveats — what this is and isn't

- **PUBLISHED records only.** CVEs that are RESERVED (an ID exists but no details
  yet) or REJECTED (withdrawn) aren't here. A CVE that gets rejected later is
  removed from the dataset.
- **A daily snapshot, not real-time.** Upstream updates roughly every 7 minutes;
  this refreshes once a day.
- **Compact encodings:** `cisa_kev` is `1`/`0`, the date columns are calendar
  dates (`YYYY-MM-DD`, no time of day), and the `cpes`/multi-value lists are
  capped at 50 entries with a `…(+N)` marker.
- **English descriptions only.**
- **Not a replacement for NVD's full CPE configurations.** If you're doing
  serious automated asset matching with complex version ranges, treat `cpes`
  here as a starting filter and confirm against [NVD](https://nvd.nist.gov).
- This is an independent project that re-packages public CVE data; it isn't
  affiliated with MITRE, NIST/NVD, or CISA.

## Run or rebuild it yourself

```bash
pip install -r requirements.txt          # runtime needs only: requests
python -m src.build --mode full --limit 2000 --no-commit   # quick dry run
pip install -r requirements-dev.txt && python -m pytest -q # the test suite
```

The daily refresh is `.github/workflows/daily-update.yml`. To force a full
rebuild from scratch: **Actions → Daily CVE refresh → Run workflow → mode =
full**. The build uses only the Python standard library plus `requests`; pandas
is only needed for the tests.
