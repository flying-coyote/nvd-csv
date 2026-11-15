"""Check restored shard CSVs against the SHA-256 manifest in data/state.json.

    python -m src.verify --data-dir data

The daily workflow downloads yesterday's shards from the ``latest`` GitHub
Release before building, because a delta build upserts into the existing files.
If the release and the committed state.json disagree (an upload landed but the
push didn't, or the reverse, or a file is missing), building a delta on top of
the wrong base would silently corrupt the dataset. So on any mismatch this
deletes every shard CSV, and ``--mode auto`` then falls back to a full rebuild.

A state.json written before the manifest existed has no ``sha256`` entries; in
that case the files are left alone (the legacy git-tracked copies seed the
first release). Always exits 0: a mismatch is handled by rebuilding, not by
failing the run.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import shards, state as state_mod


def verify(data_dir: str) -> str:
    """Return 'ok', 'legacy' (no manifest), or 'mismatch' (shards deleted)."""
    state = state_mod.load_state(data_dir)
    expected = {name: s.get("sha256") for name, s in (state.get("shards") or {}).items()}
    if not expected or not all(expected.values()):
        return "legacy"

    present = {os.path.splitext(os.path.basename(p))[0]: p
               for p in shards.list_shard_files(data_dir)}
    problems = []
    for name, sha in sorted(expected.items()):
        path = present.get(name)
        if path is None:
            problems.append(f"{name}: missing")
        elif shards.sha256_of(path) != sha:
            problems.append(f"{name}: sha256 mismatch")
    for name in sorted(set(present) - set(expected)):
        # e.g. an old-band asset still on the release after --band-uppers moved;
        # the manifest's names are authoritative, so drop it rather than force a
        # full rebuild every day.
        print(f"  - {name}: not in manifest, removing", flush=True)
        os.remove(present.pop(name))

    if not problems:
        return "ok"
    for p in problems:
        print(f"  ✗ {p}", flush=True)
    for path in present.values():
        os.remove(path)
    return "mismatch"


def main(argv=None):
    p = argparse.ArgumentParser(prog="src.verify")
    p.add_argument("--data-dir", default="data")
    args = p.parse_args(argv)
    result = verify(args.data_dir)
    msg = {
        "ok": "restored shards match state.json manifest — delta build can proceed",
        "legacy": "state.json has no sha256 manifest yet — leaving shards as found",
        "mismatch": "restored shards do NOT match state.json — deleted them; "
                    "auto mode will do a full rebuild",
    }[result]
    print(f"verify: {msg}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
