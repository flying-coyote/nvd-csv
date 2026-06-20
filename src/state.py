"""Load/save data/state.json — the run cursor and shard inventory.

Shape (schema_version 1):

    {
      "schema_version": 1,
      "last_run_utc": "...",
      "last_processed_fetchTime": "...",   # max deltaLog fetchTime incorporated
      "run_mode_last": "full" | "delta",
      "total_rows": 0,
      "kev_catalog_date": "...",
      "split_years": [2024, 2025],         # years auto-split into bucket sub-shards
      "shards": { "<name>": {"rows": N, "bytes": N, "year_min": Y, "year_max": Y} }
    }
"""

from __future__ import annotations

import json
import os

SCHEMA_VERSION = 1


def default_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_run_utc": None,
        "last_processed_fetchTime": None,
        "run_mode_last": None,
        "total_rows": 0,
        "kev_catalog_date": None,
        "split_years": [],
        "shards": {},
    }


def state_path(data_dir: str) -> str:
    return os.path.join(data_dir, "state.json")


def load_state(data_dir: str) -> dict:
    path = state_path(data_dir)
    if not os.path.exists(path):
        return default_state()
    with open(path, encoding="utf-8") as fh:
        loaded = json.load(fh)
    # merge onto defaults so older/partial state files gain new keys
    state = default_state()
    state.update(loaded)
    return state


def save_state(data_dir: str, state: dict) -> None:
    os.makedirs(data_dir, exist_ok=True)
    with open(state_path(data_dir), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write("\n")
