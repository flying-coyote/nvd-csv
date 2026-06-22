---
repo: nvd-csv
date: 2026-06-21
source: WF-C intent self-audit
---

# nvd-csv — intent self-audit (2026-06-21)

Method: the portable intent question bank in
`/home/jerem/claude-code-project-best-practices/analysis/intent-alignment-audit.md`,
run against the live tree. Every claim below cites a real file:line I read.
This is a small, young utility repo (initial commit 2026-06-19, two days old at
audit time), so the audit is proportionate — short, with one finding that
actually matters.

## What this repo is FOR (Q1 — Goal)

One sentence: turn the ~342k published CVE records (CVE Program JSON + NVD/CISA
enrichment) into three plain CSV shards, one row per CVE, refreshed daily, so a
junior analyst can open the whole disclosed-vulnerability history in Excel /
pandas / DuckDB with no API key and no JSON parsing.

The goal is stated cleanly and consistently. `README.md:1-13` ("every published
CVE as a CSV you can actually open") and `README.md:14-35` ("Why this exists")
agree with the actual mechanism: `src/build.py` produces `data/shards/*.csv`
(three files, confirmed on disk), the schema is 19 columns
(`README.md:80-94`), and the daily GitHub Actions workflow
(`.github/workflows/daily-update.yml:3-6`) fires the refresh. No goal-drift
across surfaces — the README, the build docstring (`src/build.py:1-12`), and the
workflow all describe the same thing. There is no `CLAUDE.md` / `AGENTS.md`, and
for a repo this size that's fine; the README carries the intent.

## Does the structure still serve that? (Q2 — Self-model)

Yes, and the self-model is honest. `data/state.json` is a machine-written model
of the dataset (per-shard `rows`/`bytes`/`year_min`/`year_max`, `total_rows:
341899`) and the README stats table is regenerated from the same numbers into a
`<!-- STATS:START -->…STATS:END -->` block by the build itself
(`src/build.py:320-326`), so the most drift-prone surface (a hand-typed row
count) is generated, not recalled — exactly the Q2 promotion the audit bank
recommends. The committed shard byte-sizes in the README table
(`README.md:70-77`) match the on-disk file sizes and `data/state.json`. One
recent commit (`b908c55 "README: correct stats table to actual committed shard
sizes"`) shows the author already caught and closed one stats-drift instance by
hand before wiring it tighter. Layout is small and legible: `src/` (5 modules,
1,191 LoC total), `tests/` (43 test functions across three files plus 7 JSON
fixtures), `excel/merge-shards.pq`, `data/`. Nothing abandoned, no stale dirs.

## Where it is most likely WRONG (Q5) — the one real finding

The README sells the loop as a *delta-first, self-healing* daily refresh:
"Most days it only fetches the handful of records that changed upstream (it
follows the CVE Program's own `deltaLog.json` change feed) and commits a small
update… If the change feed ever rolls past where we left off, the build rebuilds
the whole dataset from scratch automatically, so it's self-healing"
(`README.md:215-223`). The delta path is real and well-written
(`src/build.py:164-255`, `decide_mode` at `src/build.py:76-88`,
`sources.changes_since` at `src/sources.py:73-91`).

But the committed run history shows that path has **never actually run on the
schedule**. `data/changes/CHANGELOG.md` records seven runs, every one of them
`full`, all dated 2026-06-20:

    - 2026-06-20 · **full** · +341899 / ~0 / -0 · 341,899 total rows   (×6, plus one +341897)

and `data/changes/changes_2026-06-20.csv` is header-only (zero change rows). The
cause is benign — these seven `full` commits are the author iterating on the
schema during the two-day build-out (`Trim schema to 18 columns`,
`Keep cpes (19 cols)`, `Rebalance bands`, `Date columns to calendar date`), each
landed by a forced `workflow_dispatch mode=full`. The scheduled `cron: "0 7 * * *"`
delta refresh (`daily-update.yml:4-6`) has not yet had a quiet day to prove
itself, so the dominant *intended* code path (delta) is the one with zero
observed successful production runs. This is the classic strong-Act /
stale-Orient shape from the audit bank, in miniature: the machinery to act on a
cadence is present and the verification (tests, errexit on push) keeps each
*action* honest, but nothing yet confirms the loop is doing the *intended* thing
rather than silently always falling back to `full`. A `full` rebuild clones the
~360k-file upstream repo every run (`src/sources.py:148-158`, `timeout-minutes:
180`), so a delta path that quietly never engages would be a 100×-cost
regression that produces correct data and therefore raises no error.

Where it's most likely wrong, concretely: `decide_mode` returns `full` whenever
`last < oldest` (`src/build.py:86-87`), i.e. whenever the deltaLog window has
rolled past our cursor. The deltaLog is a rolling window; if a scheduled run is
ever skipped or the window is shorter than ~24h of upstream churn, the guard
correctly rebuilds — but if that condition is met *most* days, the repo would
run `full` daily forever and look healthy. There is no eval that asserts "a
normal day should be `delta`."

## RETHINK / intent-check instrument (the Q3/loop question)

Effectively absent, and that's the gap worth naming. The loop has good
*action-level* verification: the test suite (43 tests), `raise_on_status` retries
(`src/sources.py:36-49`), errexit-guarded push that aborts rather than push stale
data (`daily-update.yml:55-58`), and `concurrency` serialization
(`daily-update.yml:18-21`). What it lacks is the outer-loop check that the run
was the *kind* of run it was supposed to be. `CHANGELOG.md` is the natural place
for it — it already logs `date · mode · added/updated/removed · total` per run —
but nothing reads it back to flag "7 consecutive `full` runs" or "today was
`full` on a scheduled trigger." The cheapest fix: have the workflow (or a tiny
assertion in `build.py`) warn when a *scheduled* (non-dispatch) run resolves to
`full`, since on the steady state that should be rare. That converts the silent
strong-Act/stale-Orient failure into a visible signal.

## Autonomy boundary (Q4)

`permissions: contents: write` (`daily-update.yml:15-16`) is correctly scoped —
the job's whole job is to commit regenerated data, so write is the right rung
here (unlike the best-practices repo's finding where a *read-only* tracker held
write). It commits against its own generated `data/` and `README.md` only
(`git add data/ README.md`, `daily-update.yml:50-54`), rebases before push, and
serializes via `concurrency`. The blast radius is bounded to this repo's data.
No secrets in the tree; the only network deps are public CVE/KEV endpoints
(`src/sources.py:23-30`). This is a well-drawn autonomy boundary for an
unattended daily committer.

## Dead weight

Almost none — the repo is two days old and was just through a `Ponytail
cleanup: drop dead code` pass (`44bd1b1`). Minor items only:

- `data/changes/CHANGELOG.md` carries six near-identical `full` lines from the
  build-out iteration; once a real delta cadence starts these are noise. Not
  worth editing now (the workflow appends), but the first real delta day is the
  moment to confirm the log starts reading one-line-per-day as intended.
- `.pytest_cache/`, `__pycache__/`, `src/__pycache__/`, `tests/__pycache__/`
  are present on disk but correctly gitignored (`.gitignore`), so not committed
  dead weight — just local artifacts.

## Bus-factor (Q9)

Single-author repo, but the bus-factor is low *because the knowledge is in the
code and README, not in the author's head.* The build is pure-stdlib + `requests`
(`requirements.txt`), the upstream contract is documented inline
(`src/sources.py:1-30`), and the README explains every column and the
full-vs-delta logic to a junior-analyst audience. The one piece of tribal
knowledge that isn't written down is the `date_updated` provenance decision —
the README (`README.md:100-104`) explains *that* the code reads the record's own
provider metadata instead of `cveMetadata.dateUpdated` (because a 2024 bulk
migration stamped ~46% of records), which is a genuinely subtle, easy-to-regress
choice; if someone "simplified" the parser back to the top-level field, ~46% of
`date_updated` values would silently go wrong and no test obviously guards it.
That parsing rule is the single most fragile one-person dependency.

## Honest bottom line

This is a clean, well-scoped, well-documented small utility repo that is doing
exactly what it says. The structure serves the goal, the self-model is generated
rather than hand-maintained, and the autonomy boundary is correct. The only
finding that matters is that the *intended* (delta, self-healing) loop has zero
observed scheduled runs yet — every committed run is a forced `full` from the
two-day build-out — and there is no instrument that would tell the author if the
loop silently ran `full` forever. Add a "scheduled run resolved to full" warning
and watch the first real cron day; everything else is fine as-is.
