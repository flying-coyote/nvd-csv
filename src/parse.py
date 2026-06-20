"""CVE JSON 5.x record -> single flat row dict.

All of the schema logic lives here: column order, the CNA-first CVSS/CWE
precedence, x_transferred reference de-duplication, SSVC extraction, KEV join,
and cell hygiene (newline/tab collapse, " | " flattening, list caps).

Standard library only. No I/O — callers hand in a parsed dict and (optionally)
a KEV index; the row that comes back is all strings, ready for csv.DictWriter.

Schema note: the column set was trimmed from the original 35 to 27 to save
space — dropped columns (state, year, assigner_org_id, data_version,
has_cisa_adp, source_path, record_dateUpdated_hash, reference_urls) were either
constant, derivable from cve_id, or low-value-per-byte. The derivation helpers
(year_of/bucket_of/source_path_for) stay because sharding still uses them.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Column order (the single source of truth; shards.py imports this).
# ---------------------------------------------------------------------------
COLUMNS = [
    # identity
    "cve_id", "assigner_short_name",
    # dates
    "date_reserved", "date_published", "date_updated",
    # text
    "title", "description_en",
    # severity (single best value + source)
    "cvss_version", "cvss_base_score", "cvss_base_severity", "cvss_vector",
    "cvss_source",
    # weakness (single best value + source, plus all-IDs aggregate)
    "cwe_id", "cwe_name", "cwe_source", "cwe_ids_all",
    # CISA enrichment (ADP-only signals)
    "cisa_kev", "kev_date_added", "kev_known_ransomware",
    "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
    # affected
    "vendors", "products", "affected_count", "cpes",
    # references
    "reference_count",
]

LIST_DELIM = " | "
LIST_CAP = 50          # cap for cpes
OVERFLOW = "…"    # the … used in "…(+N)" markers and --max-desc truncation

# CVSS metric keys mapped to (canonical version string, comparable rank).
# Highest rank wins "highest version within container": v4.0 > v3.1 > v3.0 > v2.0.
_CVSS_KEYS = {
    "cvssV4_0": ("4.0", 40),
    "cvssV3_1": ("3.1", 31),
    "cvssV3_0": ("3.0", 30),
    "cvssV2_0": ("2.0", 20),
}

_CWE_RE = re.compile(r"^CWE-\d+$")
_WS_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _clean(value) -> str:
    """Collapse all internal whitespace (newlines, tabs, runs) to single spaces."""
    if value is None:
        return ""
    return _WS_RE.sub(" ", str(value)).strip()


def _num(value) -> str:
    """Numbers stringified as-is (a JSON int 10 stays "10"); None -> ""."""
    return "" if value is None else str(value)


def _flatten(values, cap: int | None = None) -> str:
    """De-dup order-stable, clean each cell, join with ' | '.

    With ``cap`` set, keep the first ``cap`` distinct values and append a
    ``…(+N)`` element for the remainder.
    """
    distinct, seen = [], set()
    for v in values:
        v = _clean(v)
        if v and v not in seen:
            seen.add(v)
            distinct.append(v)
    if cap is not None and len(distinct) > cap:
        n = len(distinct) - cap
        return LIST_DELIM.join(distinct[:cap] + [f"{OVERFLOW}(+{n})"])
    return LIST_DELIM.join(distinct)


def _shortname(container) -> str:
    if not isinstance(container, dict):
        return ""
    return (container.get("providerMetadata") or {}).get("shortName") or ""


# ---------------------------------------------------------------------------
# identity derivations (stable from the CVE ID alone)
# ---------------------------------------------------------------------------
def cve_id_of(record) -> str:
    return (record.get("cveMetadata") or {}).get("cveId") or ""


def state_of(record) -> str:
    return (record.get("cveMetadata") or {}).get("state") or ""


def is_published(record) -> bool:
    return state_of(record) == "PUBLISHED"


def year_of(cve_id: str) -> str:
    return cve_id.split("-")[1]


def bucket_of(cve_id: str) -> str:
    """Thousands bucket as used in the upstream tree: 38595 -> '38xxx', 7 -> '0xxx'."""
    seq = int(cve_id.split("-")[2])
    return f"{seq // 1000}xxx"


def source_path_for(cve_id: str) -> str:
    """Upstream path for a CVE — used by sharding; no longer an output column."""
    return f"cves/{year_of(cve_id)}/{bucket_of(cve_id)}/{cve_id}.json"


# ---------------------------------------------------------------------------
# severity (CVSS)
# ---------------------------------------------------------------------------
def derive_severity(score) -> str:
    """CVSS v3.1 qualitative bands, used only when baseSeverity is absent."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return "NONE"
    if s < 4.0:
        return "LOW"
    if s < 7.0:
        return "MEDIUM"
    if s < 9.0:
        return "HIGH"
    return "CRITICAL"


def _best_cvss(container):
    """Highest-version CVSS within one container, or None."""
    if not isinstance(container, dict):
        return None
    best = None  # (rank, payload)
    for metric in (container.get("metrics") or []):
        if not isinstance(metric, dict):
            continue
        for key, (vstr, rank) in _CVSS_KEYS.items():
            block = metric.get(key)
            if isinstance(block, dict) and block.get("baseScore") is not None:
                if best is None or rank > best[0]:
                    best = (rank, {
                        "version": block.get("version") or vstr,
                        "score": block.get("baseScore"),
                        "severity": (block.get("baseSeverity")
                                     or derive_severity(block.get("baseScore"))),
                        "vector": block.get("vectorString") or "",
                    })
    return best[1] if best else None


def _cvss_fields(cna, cisa) -> dict:
    chosen, source = _best_cvss(cna), "cna"
    if chosen is None and cisa is not None:
        chosen = _best_cvss(cisa)
        source = "cisa-adp"
    if chosen is None:
        return {k: "" for k in
                ("cvss_version", "cvss_base_score", "cvss_base_severity",
                 "cvss_vector", "cvss_source")}
    return {
        "cvss_version": _clean(chosen["version"]),
        "cvss_base_score": _num(chosen["score"]),
        "cvss_base_severity": _clean(chosen["severity"]),
        "cvss_vector": _clean(chosen["vector"]),
        "cvss_source": source,
    }


# ---------------------------------------------------------------------------
# weakness (CWE)
# ---------------------------------------------------------------------------
def _cwes_in(container):
    """[(cweId, description)] for valid CWE-\\d+ ids only, order preserved."""
    if not isinstance(container, dict):
        return []
    out = []
    for pt in (container.get("problemTypes") or []):
        if not isinstance(pt, dict):
            continue
        for desc in (pt.get("descriptions") or []):
            if not isinstance(desc, dict):
                continue
            cid = _clean(desc.get("cweId"))
            if _CWE_RE.match(cid):
                out.append((cid, _clean(desc.get("description"))))
    return out


def _cwe_fields(cna, adp_list) -> dict:
    cna_cwes = _cwes_in(cna)
    primary, source = None, ""
    if cna_cwes:
        primary, source = cna_cwes[0], "cna"
    else:
        for adp in adp_list:
            adp_cwes = _cwes_in(adp)
            if adp_cwes:
                primary, source = adp_cwes[0], "cisa-adp"
                break
    all_ids, seen = [], set()
    for cid, _name in cna_cwes:
        if cid not in seen:
            seen.add(cid)
            all_ids.append(cid)
    for adp in adp_list:
        for cid, _name in _cwes_in(adp):
            if cid not in seen:
                seen.add(cid)
                all_ids.append(cid)
    return {
        "cwe_id": primary[0] if primary else "",
        "cwe_name": primary[1] if primary else "",
        "cwe_source": source,
        "cwe_ids_all": LIST_DELIM.join(all_ids),
    }


# ---------------------------------------------------------------------------
# SSVC (CISA-ADP only)
# ---------------------------------------------------------------------------
def _ssvc_fields(cisa) -> dict:
    out = {"ssvc_exploitation": "", "ssvc_automatable": "",
           "ssvc_technical_impact": ""}
    if not cisa:
        return out
    for metric in (cisa.get("metrics") or []):
        if not isinstance(metric, dict):
            continue
        other = metric.get("other") or {}
        if other.get("type") == "ssvc":
            kv = {}
            for opt in ((other.get("content") or {}).get("options") or []):
                if isinstance(opt, dict):
                    for k, v in opt.items():
                        kv[k.strip().lower()] = _clean(v)
            out["ssvc_exploitation"] = kv.get("exploitation", "")
            out["ssvc_automatable"] = kv.get("automatable", "")
            out["ssvc_technical_impact"] = kv.get("technical impact", "")
            break
    return out


# ---------------------------------------------------------------------------
# affected / cpes / references
# ---------------------------------------------------------------------------
def _affected_fields(cna) -> dict:
    affected = cna.get("affected") or []
    vendors, products = [], []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        vendor = _clean(entry.get("vendor"))
        product = _clean(entry.get("product"))
        if vendor and vendor.lower() != "n/a":
            vendors.append(vendor)
        if product and product.lower() != "n/a":
            products.append(product)
    return {
        "vendors": _flatten(vendors),
        "products": _flatten(products),
        "affected_count": str(len(affected)),
    }


def _cpe_values(cna, adp_list):
    cpes = []
    for container in [cna] + list(adp_list):
        if not isinstance(container, dict):
            continue
        for entry in (container.get("affected") or []):
            if isinstance(entry, dict):
                cpes.extend(entry.get("cpes") or [])
        for applic in (container.get("cpeApplicability") or []):
            if not isinstance(applic, dict):
                continue
            for node in (applic.get("nodes") or []):
                if not isinstance(node, dict):
                    continue
                for match in (node.get("cpeMatch") or []):
                    if isinstance(match, dict) and match.get("criteria"):
                        cpes.append(match["criteria"])
    return cpes


def _reference_count(cna, adp_list) -> dict:
    """Distinct reference URLs across CNA + ADP, dropping x_transferred copies.

    Only the count survives in the schema (the URL list itself was the single
    largest low-value column); the dedup still runs so the count is honest.
    """
    seen = set()

    def add(url):
        url = _clean(url)
        if url:
            seen.add(url)

    for ref in (cna.get("references") or []):
        if isinstance(ref, dict):
            add(ref.get("url"))
    for adp in adp_list:
        if not isinstance(adp, dict):
            continue
        for ref in (adp.get("references") or []):
            if not isinstance(ref, dict):
                continue
            if "x_transferred" in (ref.get("tags") or []):
                continue  # one-time CNA copy added by the CVE Program container
            add(ref.get("url"))
    return {"reference_count": str(len(seen))}


# ---------------------------------------------------------------------------
# text & KEV
# ---------------------------------------------------------------------------
def _description_en(cna, max_desc_chars: int) -> str:
    parts = []
    for desc in (cna.get("descriptions") or []):
        if not isinstance(desc, dict):
            continue
        if (desc.get("lang") or "").lower().startswith("en"):
            value = _clean(desc.get("value"))
            if value:
                parts.append(value)
    text = _clean(" ".join(parts))
    if max_desc_chars and max_desc_chars > 0 and len(text) > max_desc_chars:
        text = text[:max_desc_chars] + OVERFLOW
    return text


def _kev_fields(cve_id, kev_index) -> dict:
    entry = kev_index.get(cve_id) if kev_index else None
    if entry is None:
        return {"cisa_kev": "false", "kev_date_added": "",
                "kev_known_ransomware": ""}
    return {
        "cisa_kev": "true",
        "kev_date_added": _clean(entry.get("dateAdded")),
        "kev_known_ransomware": _clean(entry.get("knownRansomwareCampaignUse")),
    }


def kev_fields(cve_id, kev_index) -> dict:
    """Public: the three KEV columns for one CVE. Used to refresh KEV-only
    changes onto an existing row during a delta run without re-fetching it."""
    return _kev_fields(cve_id, kev_index)


# ---------------------------------------------------------------------------
# the public entry point
# ---------------------------------------------------------------------------
def record_to_row(record, kev_index=None, max_desc_chars: int = 0) -> dict:
    """Flatten one CVE JSON 5.x record into a {column: str} row.

    ``kev_index`` maps cve_id -> {"dateAdded", "knownRansomwareCampaignUse"};
    pass the parsed CISA KEV catalog. ``max_desc_chars`` of 0 means no
    description truncation.
    """
    meta = record.get("cveMetadata") or {}
    cve_id = meta.get("cveId") or ""
    containers = record.get("containers") or {}
    cna = containers.get("cna")
    cna = cna if isinstance(cna, dict) else {}
    adp_list = containers.get("adp")
    adp_list = adp_list if isinstance(adp_list, list) else []
    cisa = next((a for a in adp_list if _shortname(a) == "CISA-ADP"), None)

    row = {col: "" for col in COLUMNS}
    row["cve_id"] = cve_id
    row["assigner_short_name"] = _clean(meta.get("assignerShortName"))
    row["date_reserved"] = _clean(meta.get("dateReserved"))
    row["date_published"] = _clean(meta.get("datePublished"))
    row["date_updated"] = _clean(meta.get("dateUpdated"))
    row["title"] = _clean(cna.get("title"))
    row["description_en"] = _description_en(cna, max_desc_chars)
    row.update(_cvss_fields(cna, cisa))
    row.update(_cwe_fields(cna, adp_list))
    row.update(_kev_fields(cve_id, kev_index))
    row.update(_ssvc_fields(cisa))
    row.update(_affected_fields(cna))
    row["cpes"] = _flatten(_cpe_values(cna, adp_list), cap=LIST_CAP)
    row.update(_reference_count(cna, adp_list))
    return row
