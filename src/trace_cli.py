import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

import yaml


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"❌ YAML not found: {path}")
    except Exception as e:
        raise SystemExit(f"❌ Failed to parse YAML {path}: {e}")
    if not isinstance(data, dict):
        raise SystemExit(f"❌ YAML root must be a mapping/object: {path}")
    return data


def read_jsonl(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        raise SystemExit(f"❌ JSONL not found: {path}")

    records = []
    for i, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            raise SystemExit(f"❌ JSONL parse error in {path} line {i}: {e}")
        if not isinstance(rec, dict):
            raise SystemExit(f"❌ JSONL line {i} must be an object/dict")
        records.append(rec)
    return records


def validate_gate_config(cfg: dict) -> None:
    if "version" not in cfg or not isinstance(cfg["version"], (str, int, float)):
        raise SystemExit("❌ gate_config.yaml must include: version")
    if "gates" not in cfg or not isinstance(cfg["gates"], list):
        raise SystemExit("❌ gate_config.yaml must include: gates: [ ... ]")

    for idx, g in enumerate(cfg["gates"], start=1):
        if not isinstance(g, dict):
            raise SystemExit(f"❌ gate_config.yaml gate #{idx} must be an object")
        for k in ("id", "name", "level"):
            if k not in g:
                raise SystemExit(f"❌ gate_config.yaml gate #{idx} missing '{k}'")
        if g["level"] not in ("pass", "escalate", "hard_stop"):
            raise SystemExit(
                f"❌ gate_config.yaml gate #{idx} level must be pass|escalate|hard_stop"
            )


def validate_permission_sets(cfg: dict) -> None:
    if "version" not in cfg or not isinstance(cfg["version"], (str, int, float)):
        raise SystemExit("❌ permission_sets.yaml must include: version")
    if "sets" not in cfg or not isinstance(cfg["sets"], list):
        raise SystemExit("❌ permission_sets.yaml must include: sets: [ ... ]")

    for idx, s in enumerate(cfg["sets"], start=1):
        if not isinstance(s, dict):
            raise SystemExit(f"❌ permission_sets.yaml set #{idx} must be an object")
        for k in ("id", "name", "allowed_gates"):
            if k not in s:
                raise SystemExit(f"❌ permission_sets.yaml set #{idx} missing '{k}'")
        if not isinstance(s["allowed_gates"], list):
            raise SystemExit(f"❌ permission_sets.yaml set #{idx} allowed_gates must be a list")


def cmd_hello(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hello.txt").write_text(
        f"TRACE CLI is working. UTC={utc_now_iso()}\n", encoding="utf-8"
    )
    print("✅ TRACE CLI is working. Wrote out/hello.txt")


def cmd_validate(gate_path: Path, perms_path: Path) -> None:
    gate_cfg = read_yaml(gate_path)
    perms_cfg = read_yaml(perms_path)

    validate_gate_config(gate_cfg)
    validate_permission_sets(perms_cfg)

    gate_ids = {g["id"] for g in gate_cfg["gates"]}
    for s in perms_cfg["sets"]:
        for gid in s["allowed_gates"]:
            if gid not in gate_ids:
                raise SystemExit(f"❌ permission_sets references unknown gate id: {gid}")

    print("✅ Config validation passed:")
    print(f"   - gates: {len(gate_cfg['gates'])}")
    print(f"   - permission sets: {len(perms_cfg['sets'])}")


def cmd_run(scenarios_path: Path, out_root: Path) -> None:
    scenarios = read_jsonl(scenarios_path)
    if not scenarios:
        raise SystemExit("❌ No scenarios found in scenario pack.")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    packets_dir = out_root / "packets" / run_id
    runs_dir = out_root / "runs" / run_id
    packets_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for scn in scenarios:
        scn_id = scn.get("id", f"row_{written+1}")
        packet = {
            "run_id": run_id,
            "created_utc": utc_now_iso(),
            "scenario": scn,
            "result": {
                "status": "pass",
                "notes": "Demo run output (placeholder)."
            }
        }
        (packets_dir / f"packet_{scn_id}.json").write_text(
            json.dumps(packet, indent=2), encoding="utf-8"
        )
        written += 1

    summary = {
        "run_id": run_id,
        "created_utc": utc_now_iso(),
        "scenario_count": len(scenarios),
        "packets_written": written,
        "packets_dir": str(packets_dir),
    }
    (runs_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("✅ Run complete")
    print(f"   - run_id: {run_id}")
    print(f"   - packets: {written} -> {packets_dir}")
    print(f"   - summary: {runs_dir / 'run_summary.json'}")


def main():
    parser = argparse.ArgumentParser(prog="trace-cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hello = sub.add_parser("hello", help="Smoke test; writes out/hello.txt")
    p_hello.add_argument("--out", default="out", help="Output directory root (default: out)")

    p_val = sub.add_parser("validate", help="Validate configs")
    p_val.add_argument("--gate", default="configs/gate_config.yaml")
    p_val.add_argument("--perms", default="configs/permission_sets.yaml")

    p_run = sub.add_parser("run", help="Run scenario pack -> write packets")
    p_run.add_argument("--scenarios", default="scenarios/scenario_pack_v0.jsonl")
    p_run.add_argument("--out", default="out", help="Output directory root (default: out)")

    args = parser.parse_args()

    if args.cmd == "hello":
        cmd_hello(Path(args.out))
    elif args.cmd == "validate":
        cmd_validate(Path(args.gate), Path(args.perms))
    elif args.cmd == "run":
        cmd_run(Path(args.scenarios), Path(args.out))


if __name__ == "__main__":
    main()
