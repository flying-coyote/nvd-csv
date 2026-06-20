"""Tests for src/parse.py — the record -> row builder (18-column schema).

Real fixtures are frozen upstream snapshots (so their exact values are stable
and safe to assert on); synthetic fixtures cover the cases that don't occur in
real data (CVSS in both containers) or that need byte-exact known inputs.
"""
import csv
import io
import json
import os

import pytest

from src import parse

FIXDIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXDIR, name), encoding="utf-8") as fh:
        return json.load(fh)


def row(name, **kw):
    return parse.record_to_row(load(name), **kw)


# ---------------------------------------------------------------------------
# schema shape
# ---------------------------------------------------------------------------
def test_columns_are_19_unique():
    assert len(parse.COLUMNS) == 19
    assert len(set(parse.COLUMNS)) == 19


def test_row_has_exactly_the_columns_and_all_strings():
    r = row("CVE-2024-1086.json")
    assert list(r.keys()) == parse.COLUMNS
    assert all(isinstance(v, str) for v in r.values())


# ---------------------------------------------------------------------------
# CVSS precedence (version / score / vector / source; severity is dropped)
# ---------------------------------------------------------------------------
def test_cvss_cna_wins_over_adp_and_highest_version_in_container():
    # synthetic: CNA has v3.1(5.0) AND v4.0(6.9); CISA-ADP has v3.1(9.9).
    r = row("synthetic-precedence.json")
    assert r["cvss_source"] == "cna"
    assert r["cvss_version"] == "4.0"
    assert r["cvss_base_score"] == "6.9"
    assert r["cvss_vector"].startswith("CVSS:4.0/")


def test_cvss_falls_back_to_cisa_adp_when_cna_has_none():
    r = row("CVE-2021-44228.json")  # Log4Shell: CVSS only in CISA-ADP
    assert r["cvss_source"] == "cisa-adp"
    assert r["cvss_version"] == "3.1"
    assert r["cvss_base_score"] == "10"          # stored as JSON int, preserved


def test_cvss_from_cna_when_present():
    r = row("CVE-2024-1086.json")
    assert r["cvss_source"] == "cna"
    assert r["cvss_base_score"] == "7.8"


def test_cvss_empty_when_neither_container_has_it():
    for name in ("CVE-2024-38595.json", "CVE-2025-40039.json"):
        r = row(name)
        assert r["cvss_version"] == ""
        assert r["cvss_base_score"] == ""
        assert r["cvss_vector"] == ""
        assert r["cvss_source"] == ""


# ---------------------------------------------------------------------------
# CWE: all distinct ids across containers
# ---------------------------------------------------------------------------
def test_cwe_ids_aggregated_across_containers():
    # CNA contributes 79, 89; CISA-ADP contributes 200 — order stable, deduped.
    r = row("synthetic-precedence.json")
    assert r["cwe_ids_all"] == "CWE-79 | CWE-89 | CWE-200"


def test_cwe_ids_real_log4shell():
    r = row("CVE-2021-44228.json")
    assert r["cwe_ids_all"] == "CWE-502 | CWE-400 | CWE-20"


def test_cwe_ids_exclude_null_and_noinfo():
    # Zerologon CNA has cweId:null (type Impact); CISA-ADP has "CWE-noinfo".
    assert row("CVE-2020-1472.json")["cwe_ids_all"] == ""


def test_cwe_ids_single_real():
    assert row("CVE-2024-1086.json")["cwe_ids_all"] == "CWE-416"


# ---------------------------------------------------------------------------
# SSVC + KEV (ransomware flag dropped)
# ---------------------------------------------------------------------------
def test_ssvc_extracted_from_cisa_adp():
    r = row("CVE-2024-38595.json")
    assert (r["ssvc_exploitation"], r["ssvc_automatable"], r["ssvc_technical_impact"]) \
        == ("none", "no", "partial")


def test_ssvc_synthetic_values():
    r = row("synthetic-precedence.json")
    assert (r["ssvc_exploitation"], r["ssvc_automatable"], r["ssvc_technical_impact"]) \
        == ("poc", "yes", "total")


def test_ssvc_empty_without_cisa_adp():
    r = row("CVE-2025-40039.json")
    assert r["ssvc_exploitation"] == ""
    assert r["ssvc_automatable"] == ""
    assert r["ssvc_technical_impact"] == ""


def test_kev_populated_from_index_and_matched_by_id():
    kev = {"CVE-2099-10001": {"dateAdded": "2099-02-15T01:02:03Z",
                              "knownRansomwareCampaignUse": "Unknown"}}
    r = row("synthetic-precedence.json", kev_index=kev)
    assert r["cisa_kev"] == "1"
    assert r["kev_date_added"] == "2099-02-15"   # date-only even if KEV gives a time


def test_kev_absent_when_not_in_index():
    r = row("synthetic-precedence.json", kev_index={"CVE-0000-0000": {}})
    assert r["cisa_kev"] == "0"
    assert r["kev_date_added"] == ""
    assert row("synthetic-precedence.json")["cisa_kev"] == "0"  # no index at all


def test_dates_reduced_to_calendar_date():
    r = row("CVE-2024-1086.json")
    assert r["date_published"] == "2024-01-31"   # was 2024-01-31T12:14:34.073Z
    # real last change = CISA-ADP enrichment 2025-10-21 (later than the CNA's date)
    assert r["date_updated"] == "2025-10-21"
    assert "T" not in r["date_published"]


def test_date_updated_recovers_real_provider_over_migration():
    # top-level dateUpdated is the 2024-08 program migration bump; the real change
    # dates live in the providers' own metadata -> use the latest of those.
    rec = {
        "cveMetadata": {"cveId": "CVE-2099-50005", "state": "PUBLISHED",
                        "datePublished": "2015-01-01T00:00:00Z",
                        "dateUpdated": "2024-08-06T07:59:00Z"},
        "containers": {
            "cna": {"providerMetadata": {"shortName": "acme",
                                         "dateUpdated": "2016-05-10T09:00:00Z"}},
            "adp": [
                {"providerMetadata": {"shortName": "CVE",          # migration -> ignored
                                      "dateUpdated": "2024-08-06T07:59:00Z"}},
                {"providerMetadata": {"shortName": "CISA-ADP",     # real enrichment
                                      "dateUpdated": "2023-11-20T00:00:00Z"}},
            ],
        },
    }
    r = parse.record_to_row(rec)
    assert r["date_published"] == "2015-01-01"
    assert r["date_updated"] == "2023-11-20"   # latest real provider, not 2024-08


def test_date_updated_nulled_when_equal_to_published():
    # CNA published and never revised: real date == published -> blank.
    rec = {
        "cveMetadata": {"cveId": "CVE-2099-50006", "state": "PUBLISHED",
                        "datePublished": "2017-04-02T20:00:00Z",
                        "dateUpdated": "2024-08-06T07:59:00Z"},   # migration bump
        "containers": {
            "cna": {"providerMetadata": {"shortName": "huawei",
                                         "dateUpdated": "2017-04-02T19:57:01Z"}},
            "adp": [{"providerMetadata": {"shortName": "CVE",
                                          "dateUpdated": "2024-08-06T07:59:00Z"}}],
        },
    }
    r = parse.record_to_row(rec)
    assert r["date_published"] == "2017-04-02"
    assert r["date_updated"] == ""             # unchanged since publish


# ---------------------------------------------------------------------------
# affected flattening
# ---------------------------------------------------------------------------
def test_multi_product_flattening_real():
    r = row("CVE-2020-1472.json")
    assert r["vendors"] == "Microsoft"            # 14 entries, one vendor
    assert len(r["products"].split(" | ")) == 14  # 14 distinct products


def test_multi_vendor_distinct_flattening_synthetic():
    r = row("synthetic-precedence.json")
    assert r["vendors"] == "Acme | Globex"        # Acme appears twice -> deduped
    assert r["products"] == "Widget | Gadget"     # Widget appears twice -> deduped


def test_cpes_collected_from_affected_and_cpeapplicability():
    # synthetic: 1.0 from CNA affected[].cpes, 2.0 from CISA-ADP cpeApplicability
    r = row("synthetic-precedence.json")
    assert r["cpes"] == ("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:* | "
                         "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*")


def test_cpes_capped_at_50_with_marker():
    rec = {
        "cveMetadata": {"cveId": "CVE-2099-30003", "state": "PUBLISHED"},
        "containers": {"cna": {"affected": [{
            "vendor": "V", "product": "P",
            "cpes": [f"cpe:2.3:a:v:p:{i}.0:*:*:*:*:*:*:*" for i in range(55)],
        }]}},
    }
    r = parse.record_to_row(rec)
    parts = r["cpes"].split(" | ")
    assert len(parts) == 51
    assert parts[-1] == "…(+5)"


# ---------------------------------------------------------------------------
# state / publication / identity derivations (functions, not columns)
# ---------------------------------------------------------------------------
def test_published_vs_rejected_state():
    assert parse.is_published(load("CVE-2024-1086.json")) is True
    assert parse.is_published(load("synthetic-rejected.json")) is False
    assert parse.state_of(load("synthetic-rejected.json")) == "REJECTED"
    assert parse.cve_id_of(load("synthetic-rejected.json")) == "CVE-2099-20002"


@pytest.mark.parametrize("cve_id,bucket,path", [
    ("CVE-2024-38595", "38xxx", "cves/2024/38xxx/CVE-2024-38595.json"),
    ("CVE-2020-1472", "1xxx", "cves/2020/1xxx/CVE-2020-1472.json"),
    ("CVE-2024-0007", "0xxx", "cves/2024/0xxx/CVE-2024-0007.json"),
    ("CVE-2025-123456", "123xxx", "cves/2025/123xxx/CVE-2025-123456.json"),
])
def test_source_path_and_bucket(cve_id, bucket, path):
    assert parse.bucket_of(cve_id) == bucket
    assert parse.source_path_for(cve_id) == path
    assert parse.year_of(cve_id) == cve_id.split("-")[1]


# ---------------------------------------------------------------------------
# description: english-only, collapse, optional truncation
# ---------------------------------------------------------------------------
def test_description_english_only_and_collapsed():
    r = row("synthetic-precedence.json")
    assert r["description_en"] == 'Line one, with a comma and a "quote" and a tab.'
    assert "espanol" not in r["description_en"]   # non-en dropped
    assert "\n" not in r["description_en"] and "\t" not in r["description_en"]


def test_description_truncation_flag():
    r = row("synthetic-precedence.json", max_desc_chars=10)
    assert r["description_en"] == "Line one, " + "…"
    assert row("synthetic-precedence.json")["description_en"].endswith("a tab.")


# ---------------------------------------------------------------------------
# robustness: non-dict junk in any array must be skipped, not crash
# ---------------------------------------------------------------------------
def test_malformed_array_entries_do_not_crash():
    rec = {
        "cveMetadata": {"cveId": "CVE-2099-40004", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": ["junk", {"lang": "en", "value": "ok"}],
                "metrics": ["junk", {"cvssV3_1": {"baseScore": 5.0, "version": "3.1"}}],
                "problemTypes": ["junk", {"descriptions":
                                          ["x", {"cweId": "CWE-79", "description": "xss"}]}],
                "affected": ["junk", {"vendor": "V", "product": "P"}],
            },
            "adp": ["junk", {"providerMetadata": {"shortName": "CISA-ADP"},
                             "metrics": ["junk", {"other": {"type": "ssvc", "content":
                                         {"options": [{"Exploitation": "none"}]}}}]}],
        },
    }
    r = parse.record_to_row(rec)
    assert r["description_en"] == "ok"
    assert r["cvss_base_score"] == "5.0"
    assert r["cwe_ids_all"] == "CWE-79"
    assert r["vendors"] == "V"
    assert r["ssvc_exploitation"] == "none"


# ---------------------------------------------------------------------------
# CSV hygiene: a nasty description round-trips with no column drift
# ---------------------------------------------------------------------------
def test_csv_roundtrip_stdlib_no_column_drift():
    r = row("synthetic-precedence.json")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=parse.COLUMNS, quoting=csv.QUOTE_MINIMAL,
                       lineterminator="\n")
    w.writeheader()
    w.writerow(r)
    buf.seek(0)
    back = list(csv.DictReader(buf))
    assert len(back) == 1
    got = back[0]
    assert list(got.keys()) == parse.COLUMNS          # no extra/missing columns
    assert got["description_en"] == r["description_en"]   # comma + quote intact
    assert got["cve_id"] == "CVE-2099-10001"


def test_csv_roundtrip_pandas_no_column_drift():
    pd = pytest.importorskip("pandas")
    r = row("synthetic-precedence.json")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=parse.COLUMNS, quoting=csv.QUOTE_MINIMAL,
                       lineterminator="\n")
    w.writeheader()
    w.writerow(r)
    buf.seek(0)
    df = pd.read_csv(buf, dtype=str, keep_default_na=False)
    assert list(df.columns) == parse.COLUMNS
    assert len(df) == 1
    assert df.iloc[0]["description_en"] == r["description_en"]
