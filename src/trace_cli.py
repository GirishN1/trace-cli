import argparse
import json
import re
from pathlib import Path
from datetime import datetime, timezone

import yaml


SEVERITY = {"PASS": 0, "ESCALATE": 1, "HARD_STOP": 2}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
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


def validate_permission_sets(cfg: dict) -> None:
    if "version" not in cfg:
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


def detect_gate_schema(gate_cfg: dict) -> str:
    # paper schema: policy_version + gates[] with outcome/if/reason_code
    if "policy_version" in gate_cfg and isinstance(gate_cfg.get("gates"), list):
        sample = gate_cfg["gates"][0] if gate_cfg["gates"] else {}
        if isinstance(sample, dict) and ("outcome" in sample or "if" in sample):
            return "paper"
    # legacy schema: version + gates[] with level/name/description
    if "version" in gate_cfg and isinstance(gate_cfg.get("gates"), list):
        return "legacy"
    return "unknown"


def validate_gate_config_paper(cfg: dict) -> None:
    if "policy_version" not in cfg:
        raise SystemExit("❌ gate_config.yaml (paper schema) must include: policy_version")
    if "gates" not in cfg or not isinstance(cfg["gates"], list):
        raise SystemExit("❌ gate_config.yaml (paper schema) must include: gates: [ ... ]")

    for idx, g in enumerate(cfg["gates"], start=1):
        if not isinstance(g, dict):
            raise SystemExit(f"❌ gate_config.yaml gate #{idx} must be an object")
        for k in ("id", "if", "outcome", "reason_code"):
            if k not in g:
                raise SystemExit(f"❌ gate_config.yaml gate #{idx} missing '{k}'")
        if g["outcome"] not in ("PASS", "ESCALATE", "HARD_STOP"):
            raise SystemExit(f"❌ gate_config.yaml gate #{idx} outcome must be PASS|ESCALATE|HARD_STOP")


def validate_gate_config_legacy(cfg: dict) -> None:
    if "version" not in cfg:
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
            raise SystemExit("❌ legacy gate level must be pass|escalate|hard_stop")


def make_getter(ctx: dict):
    def get(path: str):
        cur = ctx
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur
    return get


_DOTTED = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+\b")


def eval_paper_if(expr: str, ctx: dict) -> bool:
    # Convert paper-style to safe Python eval:
    # - true/false -> True/False
    # - evidence.count -> get("evidence.count")
    # - allow and/or/not, ==, !=, <, <=, >, >=, parentheses, numbers, strings
    expr2 = expr.replace(" true", " True").replace(" false", " False").replace("true", "True").replace("false", "False")

    def repl(m):
        return f'get("{m.group(0)}")'

    expr2 = _DOTTED.sub(repl, expr2)

    get = make_getter(ctx)
    try:
        return bool(eval(expr2, {"__builtins__": {}}, {"get": get}))
    except Exception:
        return False


def cmd_validate(gate_path: Path, perms_path: Path) -> None:
    gate_cfg = read_yaml(gate_path)
    perms_cfg = read_yaml(perms_path)

    validate_permission_sets(perms_cfg)

    schema = detect_gate_schema(gate_cfg)
    if schema == "paper":
        validate_gate_config_paper(gate_cfg)
        gate_ids = {g["id"] for g in gate_cfg["gates"]}
        policy_version = gate_cfg["policy_version"]
    elif schema == "legacy":
        validate_gate_config_legacy(gate_cfg)
        gate_ids = {g["id"] for g in gate_cfg["gates"]}
        policy_version = str(gate_cfg.get("version"))
    else:
        raise SystemExit("❌ gate_config.yaml schema not recognized (expected paper or legacy format)")

    for s in perms_cfg["sets"]:
        for gid in s["allowed_gates"]:
            if gid not in gate_ids:
                raise SystemExit(f"❌ permission_sets references unknown gate id: {gid}")

    print("✅ Config validation passed:")
    print(f"   - gate schema: {schema}")
    print(f"   - policy/version: {policy_version}")
    print(f"   - gates: {len(gate_ids)}")
    print(f"   - permission sets: {len(perms_cfg['sets'])}")


def select_permission_set(perms_cfg: dict, ps_id: str) -> dict:
    for s in perms_cfg["sets"]:
        if s["id"] == ps_id:
            return s
    raise SystemExit(f"❌ Unknown permission set id: {ps_id}")


def overall_outcome(outcomes: list[str]) -> str:
    if not outcomes:
        return "PASS"
    return max(outcomes, key=lambda x: SEVERITY.get(x, 0))


def cmd_run(scenarios_path: Path, gate_path: Path, perms_path: Path, permission_set_id: str, out_root: Path) -> None:
    scenarios = read_jsonl(scenarios_path)
    if not scenarios:
        raise SystemExit("❌ No scenarios found in scenario pack.")

    gate_cfg = read_yaml(gate_path)
    perms_cfg = read_yaml(perms_path)
    validate_permission_sets(perms_cfg)

    schema = detect_gate_schema(gate_cfg)
    if schema != "paper":
        raise SystemExit("❌ This run implementation currently expects PAPER gate schema (policy_version/outcome/if).")

    validate_gate_config_paper(gate_cfg)

    ps = select_permission_set(perms_cfg, permission_set_id)
    allowed = set(ps["allowed_gates"])

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    packets_dir = out_root / "packets" / run_id
    runs_dir = out_root / "runs" / run_id
    packets_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    counts = {"PASS": 0, "ESCALATE": 0, "HARD_STOP": 0}
    written = 0

    for scn in scenarios:
        sid = scn.get("scenario_id") or scn.get("id") or f"row_{written+1}"
        tier = scn.get("tier")
        inputs = scn.get("inputs", {})
        ctx = {"tier": tier}
        if isinstance(inputs, dict):
            # allow gates to reference evidence.*, policy.*, etc
            ctx.update(inputs)

        gate_report = []
        outcomes = []
        reason_codes = []
        required_questions = []

        for g in gate_cfg["gates"]:
            if g["id"] not in allowed:
                continue
            matched = eval_paper_if(str(g["if"]), ctx)
            if matched:
                outcomes.append(g["outcome"])
                reason_codes.append(g["reason_code"])
                if isinstance(g.get("required_questions"), list):
                    required_questions.extend(g["required_questions"])
            gate_report.append({
                "gate_id": g["id"],
                "matched": bool(matched),
                "outcome": g["outcome"] if matched else None,
                "reason_code": g["reason_code"] if matched else None,
            })

        final = overall_outcome(outcomes)
        counts[final] += 1

        packet = {
            "run_id": run_id,
            "created_utc": utc_now_iso(),
            "policy_version": gate_cfg["policy_version"],
            "permission_set_id": permission_set_id,
            "scenario": scn,
            "gate_report": gate_report,
            "decision": {
                "final_outcome": final,
                "reason_codes": reason_codes,
                "required_questions": required_questions,
            },
        }

        (packets_dir / f"packet_{sid}.json").write_text(json.dumps(packet, indent=2), encoding="utf-8")
        written += 1

    summary = {
        "run_id": run_id,
        "created_utc": utc_now_iso(),
        "policy_version": gate_cfg["policy_version"],
        "permission_set_id": permission_set_id,
        "scenario_count": len(scenarios),
        "packets_written": written,
        "outcomes": counts,
        "packets_dir": str(packets_dir),
    }
    (runs_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("✅ Run complete")
    print(f"   - run_id: {run_id}")
    print(f"   - packets: {written} -> {packets_dir}")
    print(f"   - outcomes: {counts}")
    print(f"   - summary: {runs_dir / 'run_summary.json'}")


def cmd_hello(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hello.txt").write_text(f"TRACE CLI is working. UTC={utc_now_iso()}\n", encoding="utf-8")
    print("✅ TRACE CLI is working. Wrote out/hello.txt")


def main():
    parser = argparse.ArgumentParser(prog="trace")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hello = sub.add_parser("hello", help="Smoke test; writes out/hello.txt")
    p_hello.add_argument("--out", default="out")

    p_val = sub.add_parser("validate", help="Validate configs")
    p_val.add_argument("--gate", default="configs/gate_config.yaml")
    p_val.add_argument("--perms", default="configs/permission_sets.yaml")

    p_run = sub.add_parser("run", help="Run scenario pack -> write packets (paper gates)")
    p_run.add_argument("--scenarios", default="scenarios/scenario_pack_v0.jsonl")
    p_run.add_argument("--gate", default="configs/gate_config.yaml")
    p_run.add_argument("--perms", default="configs/permission_sets.yaml")
    p_run.add_argument("--permission-set", default="PS_CONTROLLERS_DEFAULT")
    p_run.add_argument("--out", default="out")

    args = parser.parse_args()

    if args.cmd == "hello":
        cmd_hello(Path(args.out))
    elif args.cmd == "validate":
        cmd_validate(Path(args.gate), Path(args.perms))
    elif args.cmd == "run":
        cmd_run(Path(args.scenarios), Path(args.gate), Path(args.perms), args.permission_set, Path(args.out))


if __name__ == "__main__":
    main()