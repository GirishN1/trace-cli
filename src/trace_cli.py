import argparse
import json
import re
import hashlib
from pathlib import Path
from datetime import datetime, timezone

import yaml


SEVERITY = {"PASS": 0, "ESCALATE": 1, "HARD_STOP": 2}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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

    records: list[dict] = []
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
            raise SystemExit(
                f"❌ permission_sets.yaml set #{idx} allowed_gates must be a list"
            )


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
        raise SystemExit(
            "❌ gate_config.yaml (paper schema) must include: policy_version"
        )
    if "gates" not in cfg or not isinstance(cfg["gates"], list):
        raise SystemExit("❌ gate_config.yaml (paper schema) must include: gates: [ ... ]")

    for idx, g in enumerate(cfg["gates"], start=1):
        if not isinstance(g, dict):
            raise SystemExit(f"❌ gate_config.yaml gate #{idx} must be an object")
        for k in ("id", "if", "outcome", "reason_code"):
            if k not in g:
                raise SystemExit(f"❌ gate_config.yaml gate #{idx} missing '{k}'")
        if g["outcome"] not in ("PASS", "ESCALATE", "HARD_STOP"):
            raise SystemExit(
                f"❌ gate_config.yaml gate #{idx} outcome must be PASS|ESCALATE|HARD_STOP"
            )


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
    expr2 = (
        expr.replace(" true", " True")
        .replace(" false", " False")
        .replace("true", "True")
        .replace("false", "False")
    )

    def repl(m):
        return f'get("{m.group(0)}")'

    expr2 = _DOTTED.sub(repl, expr2)

    get = make_getter(ctx)

    # allow simple top-level variables like: tier
    locals_env = {"get": get}
    for k, v in ctx.items():
        if re.match(r"^[A-Za-z_]\w*$", str(k)):
            locals_env[str(k)] = v

    try:
        return bool(eval(expr2, {"__builtins__": {}}, locals_env))
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
    else:
        raise SystemExit("❌ This CLI currently expects PAPER gate schema (policy_version/outcome/if).")

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


def evaluate_scenario_paper(scn: dict, gate_cfg: dict, allowed_gate_ids: set[str]) -> dict:
    sid = scn.get("scenario_id") or scn.get("id") or "UNKNOWN"
    tier = scn.get("tier")
    workflow = scn.get("workflow")
    inputs = scn.get("inputs", {})

    ctx = {"tier": tier}
    if isinstance(inputs, dict):
        ctx.update(inputs)

    gate_report = []
    outcomes: list[str] = []
    reason_codes: list[str] = []
    required_questions: list[str] = []

    for g in gate_cfg["gates"]:
        if g["id"] not in allowed_gate_ids:
            continue

        matched = eval_paper_if(str(g["if"]), ctx)
        if matched:
            outcomes.append(g["outcome"])
            reason_codes.append(g["reason_code"])
            if isinstance(g.get("required_questions"), list):
                required_questions.extend(g["required_questions"])

        gate_report.append(
            {
                "gate_id": g["id"],
                "matched": bool(matched),
                "outcome": g["outcome"] if matched else None,
                "reason_code": g["reason_code"] if matched else None,
            }
        )

    final = overall_outcome(outcomes)

    return {
        "scenario_id": sid,
        "tier": tier,
        "workflow": workflow,
        "final_outcome": final,
        "reason_codes": reason_codes,
        "required_questions": required_questions,
        "gate_report": gate_report,
    }


def build_decision_packet(
    *,
    run_id: str,
    policy_version: str,
    permission_set_id: str,
    scn: dict,
    eval_result: dict,
) -> dict:
    sid = eval_result["scenario_id"]
    tier = eval_result.get("tier")
    workflow = eval_result.get("workflow")
    inputs = scn.get("inputs", {}) if isinstance(scn.get("inputs"), dict) else {}
    evidence = inputs.get("evidence", {}) if isinstance(inputs.get("evidence"), dict) else {}
    policy = inputs.get("policy", {}) if isinstance(inputs.get("policy"), dict) else {}
    requested_action = inputs.get("requested_action", {})

    final = eval_result["final_outcome"]

    # approvals placeholder (driven by scenario hint if present)
    escalation_to = scn.get("expected_escalation_to")
    if final == "PASS":
        approvals_required = []
        approval_status = "not_required"
    elif final == "ESCALATE":
        approvals_required = [escalation_to or "Controller approver"]
        approval_status = "pending"
    else:  # HARD_STOP
        approvals_required = [escalation_to or "2LoD Risk/Compliance + Policy owner"]
        approval_status = "blocked_pending_investigation"

    # action firewall placeholder
    action_allowed = final == "PASS"
    action_firewall = {
        "requested_action": requested_action,
        "allowed": action_allowed,
        "blocked_reason": None if action_allowed else ("requires_approval" if final == "ESCALATE" else "hard_stop"),
        "notes": "Placeholder action firewall result (paper demo).",
    }

    # short memo template
    summary = inputs.get("summary") or scn.get("summary") or ""
    memo_bullets = [
        f"Requested action: {requested_action if requested_action else '(not provided)'}",
        f"Tier/workflow: tier={tier}, workflow={workflow}",
        f"Evidence refs: {evidence.get('evidence_refs', [])}",
        f"Decision: {final} (reasons={eval_result['reason_codes']})",
    ]
    if eval_result["required_questions"]:
        memo_bullets.append(f"Required questions: {eval_result['required_questions']}")

    packet = {
        "packet_version": "DP-0.1",
        "packet_id": f"PKT_{sid}",
        "run_id": run_id,
        "created_utc": utc_now_iso(),

        # Snapshot: stable replay context
        "snapshot": {
            "scenario_id": sid,
            "tier": tier,
            "workflow": workflow,
            "policy_version": policy_version,
            "permission_set_id": permission_set_id,
        },

        # Evidence register: what was relied upon / what’s missing
        "evidence_register": {
            "count": evidence.get("count"),
            "complete": evidence.get("complete"),
            "evidence_refs": evidence.get("evidence_refs", []),
            "missing": evidence.get("missing", []),
        },

        # Gate report: deterministic gate outcomes
        "gate_report": eval_result["gate_report"],

        # Decision: final output + reason codes + required questions
        "decision": {
            "final_outcome": eval_result["final_outcome"],
            "reason_codes": eval_result["reason_codes"],
            "required_questions": eval_result["required_questions"],
        },

        # Memo: human-readable “why”
        "decision_memo": {
            "summary": summary,
            "bullets": memo_bullets,
        },

        # Approvals placeholder
        "approvals": {
            "status": approval_status,
            "required": approvals_required,
            "history": [],
        },

        # Action firewall placeholder
        "action_firewall": action_firewall,

        # Full scenario (for replay)
        "scenario": scn,
        "inputs_snapshot": inputs,
        "policy_snapshot": policy,
    }

    return packet


def cmd_run(
    scenarios_path: Path,
    gate_path: Path,
    perms_path: Path,
    permission_set_id: str,
    out_root: Path,
) -> None:
    scenarios = read_jsonl(scenarios_path)
    if not scenarios:
        raise SystemExit("❌ No scenarios found in scenario pack.")

    gate_cfg = read_yaml(gate_path)
    perms_cfg = read_yaml(perms_path)
    validate_permission_sets(perms_cfg)

    schema = detect_gate_schema(gate_cfg)
    if schema != "paper":
        raise SystemExit("❌ trace run expects PAPER gate schema (policy_version/outcome/if).")
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
        eval_result = evaluate_scenario_paper(scn, gate_cfg, allowed)
        counts[eval_result["final_outcome"]] += 1

        packet = build_decision_packet(
            run_id=run_id,
            policy_version=gate_cfg["policy_version"],
            permission_set_id=permission_set_id,
            scn=scn,
            eval_result=eval_result,
        )

        sid = eval_result["scenario_id"]
        (packets_dir / f"packet_{sid}.json").write_text(
            json.dumps(packet, indent=2), encoding="utf-8"
        )
        written += 1

    # include config hashes so the run can be audited/replayed
    summary = {
        "run_id": run_id,
        "created_utc": utc_now_iso(),
        "policy_version": gate_cfg["policy_version"],
        "permission_set_id": permission_set_id,
        "scenario_count": len(scenarios),
        "packets_written": written,
        "outcomes": counts,
        "paths": {
            "packets_dir": str(packets_dir),
            "scenarios_path": str(scenarios_path),
            "gate_config_path": str(gate_path),
            "permission_sets_path": str(perms_path),
        },
        "sha256": {
            "scenario_pack": sha256_file(scenarios_path),
            "gate_config": sha256_file(gate_path),
            "permission_sets": sha256_file(perms_path),
        },
    }
    (runs_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("✅ Run complete")
    print(f"   - run_id: {run_id}")
    print(f"   - packets: {written} -> {packets_dir}")
    print(f"   - outcomes: {counts}")
    print(f"   - summary: {runs_dir / 'run_summary.json'}")


def _norm_reason_codes(xs) -> set[str]:
    if not xs:
        return set()
    if isinstance(xs, str):
        return {xs}
    if isinstance(xs, list):
        return {str(x) for x in xs}
    return {str(xs)}


def cmd_test(
    scenarios_path: Path,
    gate_path: Path,
    perms_path: Path,
    permission_set_id: str,
) -> None:
    scenarios = read_jsonl(scenarios_path)
    if not scenarios:
        raise SystemExit("❌ No scenarios found in scenario pack.")

    gate_cfg = read_yaml(gate_path)
    perms_cfg = read_yaml(perms_path)
    validate_permission_sets(perms_cfg)

    schema = detect_gate_schema(gate_cfg)
    if schema != "paper":
        raise SystemExit("❌ trace test expects PAPER gate schema (policy_version/outcome/if).")
    validate_gate_config_paper(gate_cfg)

    ps = select_permission_set(perms_cfg, permission_set_id)
    allowed = set(ps["allowed_gates"])

    failures = []
    passed = 0

    # schema keys we expect in a “Decision Packet”
    required_packet_keys = {
        "packet_version",
        "packet_id",
        "run_id",
        "created_utc",
        "snapshot",
        "evidence_register",
        "gate_report",
        "decision",
        "decision_memo",
        "approvals",
        "action_firewall",
        "scenario",
    }

    for scn in scenarios:
        sid = scn.get("scenario_id") or scn.get("id") or "UNKNOWN"
        expected_gate = scn.get("expected_gate") or scn.get("expected_outcome")
        expected_reasons = scn.get("expected_reason_codes") or scn.get("expected_reasons")

        eval_result = evaluate_scenario_paper(scn, gate_cfg, allowed)

        # build a packet in-memory and validate structure
        packet = build_decision_packet(
            run_id="TEST_RUN",
            policy_version=gate_cfg["policy_version"],
            permission_set_id=permission_set_id,
            scn=scn,
            eval_result=eval_result,
        )
        missing_keys = sorted(list(required_packet_keys - set(packet.keys())))

        ok = True
        if expected_gate and eval_result["final_outcome"] != expected_gate:
            ok = False

        if expected_reasons is not None:
            exp_set = _norm_reason_codes(expected_reasons)
            act_set = _norm_reason_codes(eval_result["reason_codes"])
            if exp_set != act_set:
                ok = False

        if missing_keys:
            ok = False

        if ok:
            passed += 1
        else:
            failures.append(
                {
                    "scenario_id": sid,
                    "expected_gate": expected_gate,
                    "actual_gate": eval_result["final_outcome"],
                    "expected_reason_codes": expected_reasons,
                    "actual_reason_codes": eval_result["reason_codes"],
                    "missing_packet_keys": missing_keys,
                }
            )

    total = len(scenarios)
    if failures:
        print(f"❌ TEST FAIL: {passed}/{total} passed; {len(failures)} failed")
        for f in failures:
            print(f"   - {f['scenario_id']}: expected={f['expected_gate']} actual={f['actual_gate']}")
            if f["expected_reason_codes"] is not None:
                print(f"     reasons expected={f['expected_reason_codes']} actual={f['actual_reason_codes']}")
            if f["missing_packet_keys"]:
                print(f"     packet missing keys: {f['missing_packet_keys']}")
        raise SystemExit(1)

    print(f"✅ TEST PASS: {passed}/{total} scenarios matched expected outputs + packet schema")


def cmd_pack(run_id: str, out_root: Path) -> None:
    packets_dir = out_root / "packets" / run_id
    runs_dir = out_root / "runs" / run_id
    summary_path = runs_dir / "run_summary.json"

    if not packets_dir.exists():
        raise SystemExit(f"❌ Packets directory not found: {packets_dir}")
    if not summary_path.exists():
        raise SystemExit(f"❌ Run summary not found: {summary_path}")

    packet_files = [p for p in sorted(packets_dir.glob("packet_*.json")) if p.name != "packet_bundle.json"]
    if not packet_files:
        raise SystemExit(f"❌ No packet_*.json files found in: {packets_dir}")

    run_summary = json.loads(summary_path.read_text(encoding="utf-8"))

    packet_index = []
    for pf in packet_files:
        packet_index.append(
            {
                "file": pf.name,
                "sha256": sha256_file(pf),
            }
        )

    bundle = {
        "bundle_version": "BND-0.1",
        "created_utc": utc_now_iso(),
        "run_id": run_id,
        "run_summary": run_summary,
        "packet_count": len(packet_files),
        "packet_index": packet_index,
    }

    bundle_path = packets_dir / "bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    print("✅ Pack complete")
    print(f"   - run_id: {run_id}")
    print(f"   - bundle: {bundle_path}")
    print(f"   - packets indexed: {len(packet_files)}")


def cmd_hello(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hello.txt").write_text(
        f"TRACE CLI is working. UTC={utc_now_iso()}\n", encoding="utf-8"
    )
    print("✅ TRACE CLI is working. Wrote out/hello.txt")


def main():
    parser = argparse.ArgumentParser(prog="trace")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hello = sub.add_parser("hello", help="Smoke test; writes out/hello.txt")
    p_hello.add_argument("--out", default="out")

    p_val = sub.add_parser("validate", help="Validate configs")
    p_val.add_argument("--gate", default="configs/gate_config.yaml")
    p_val.add_argument("--perms", default="configs/permission_sets.yaml")

    p_run = sub.add_parser("run", help="Run scenario pack -> write decision packets (paper gates)")
    p_run.add_argument("--scenarios", default="scenarios/scenario_pack_v0.jsonl")
    p_run.add_argument("--gate", default="configs/gate_config.yaml")
    p_run.add_argument("--perms", default="configs/permission_sets.yaml")
    p_run.add_argument("--permission-set", default="PS_CONTROLLERS_DEFAULT")
    p_run.add_argument("--out", default="out")

    p_test = sub.add_parser("test", help="Regression test: expected_* + packet schema")
    p_test.add_argument("--scenarios", default="scenarios/scenario_pack_v0.jsonl")
    p_test.add_argument("--gate", default="configs/gate_config.yaml")
    p_test.add_argument("--perms", default="configs/permission_sets.yaml")
    p_test.add_argument("--permission-set", default="PS_CONTROLLERS_DEFAULT")

    p_pack = sub.add_parser("pack", help="Bundle packets + hashes for a run_id into one audit artifact")
    p_pack.add_argument("--run-id", required=True)
    p_pack.add_argument("--out", default="out")

    args = parser.parse_args()

    if args.cmd == "hello":
        cmd_hello(Path(args.out))
    elif args.cmd == "validate":
        cmd_validate(Path(args.gate), Path(args.perms))
    elif args.cmd == "run":
        cmd_run(
            Path(args.scenarios),
            Path(args.gate),
            Path(args.perms),
            args.permission_set,
            Path(args.out),
        )
    elif args.cmd == "test":
        cmd_test(
            Path(args.scenarios),
            Path(args.gate),
            Path(args.perms),
            args.permission_set,
        )
    elif args.cmd == "pack":
        cmd_pack(args.run_id, Path(args.out))


if __name__ == "__main__":
    main()
