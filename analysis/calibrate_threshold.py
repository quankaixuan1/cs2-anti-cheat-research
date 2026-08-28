#!/usr/bin/env python3
"""Select and verify a frozen risk threshold using calibration trials only."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from evaluate_trials import (
    evaluation_split,
    is_subject_row,
    is_true,
    parse_time,
    read_csv,
    truth,
    value,
    wilson,
)


def load_policy(path):
    with path.open("r", encoding="utf-8-sig") as stream:
        policy = json.load(stream)
    policy["trusted_process_sha256"] = {
        item.upper() for item in policy["trusted_process_sha256"]
    }
    return policy


def policy_score(row, policy):
    score = int(row.get("AdjustedRiskScore") or row.get("RiskScore") or 0)
    sha256 = (row.get("SourceSha256") or "").upper()
    if is_true(row.get("HasEmbeddedSignature")) and sha256 in policy["trusted_process_sha256"]:
        return min(score, int(policy["allowlisted_risk_score"]))
    return score


def trial_scores(run_dir, meta, policy):
    label = truth(meta)
    reference = (
        parse_time(value(meta, "feature_enable_time_utc"))
        or parse_time(value(meta, "application_start_time_utc"))
        or parse_time(value(meta, "trial_start_time_utc"))
    )
    strict_scores = []
    subject_scores = []
    for row in read_csv(run_dir / "handles.csv"):
        timestamp = parse_time(row.get("TimestampUtc"))
        after_activation = reference is None or timestamp is None or timestamp >= reference
        subject_match = is_subject_row(row, meta)
        subject_match = after_activation if subject_match is None else after_activation and subject_match
        score = policy_score(row, policy)
        if subject_match:
            subject_scores.append(score)
        if label != "cheat" or subject_match:
            strict_scores.append(score)
    return {
        "trial_id": value(meta, "trial_id", run_dir.name),
        "condition": value(meta, "condition", ""),
        "application_name": value(meta, "application_name", ""),
        "expected_label": label,
        "strict_handle_count": len(strict_scores),
        "strict_max_score": max(strict_scores, default=0),
        "subject_handle_count": len(subject_scores),
        "subject_max_score": max(subject_scores, default=0),
    }


def metrics(trials, threshold, score_prefix):
    def detected(row):
        return (
            row[f"{score_prefix}_handle_count"] > 0
            and row[f"{score_prefix}_max_score"] >= threshold
        )

    tp = sum(row["expected_label"] == "cheat" and detected(row) for row in trials)
    fn = sum(row["expected_label"] == "cheat" and not detected(row) for row in trials)
    fp = sum(row["expected_label"] == "benign" and detected(row) for row in trials)
    tn = sum(row["expected_label"] == "benign" and not detected(row) for row in trials)
    tpr = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    precision = tp / (tp + fp) if tp + fp else None
    f1 = (
        2 * precision * tpr / (precision + tpr)
        if precision is not None and tpr is not None and precision + tpr
        else 0.0
    )
    tpr_ci = wilson(tp, tp + fn)
    fpr_ci = wilson(fp, fp + tn)
    return {
        "threshold": threshold,
        "scope": score_prefix,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "tpr": tpr,
        "fnr": 1 - tpr if tpr is not None else None,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
        "tpr_ci95_low": tpr_ci[0],
        "tpr_ci95_high": tpr_ci[1],
        "fpr_ci95_low": fpr_ci[0],
        "fpr_ci95_high": fpr_ci[1],
    }


def write_csv(path, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("data_root", type=Path)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("CS2HandleMonitor/frozen_detection_policy.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("analysis_output/calibration"),
    )
    args = parser.parse_args()
    policy = load_policy(args.policy)
    trials = []
    for metadata_path in args.data_root.rglob("metadata.json"):
        run_dir = metadata_path.parent
        if not (run_dir / "handles.csv").exists():
            continue
        with metadata_path.open("r", encoding="utf-8-sig") as stream:
            meta = json.load(stream)
        if evaluation_split(meta) == "calibration":
            trials.append(trial_scores(run_dir, meta, policy))
    if not trials:
        raise SystemExit("No calibration trials were found.")
    trials.sort(key=lambda row: row["trial_id"])
    sweep = [
        metrics(trials, threshold, scope)
        for threshold in range(1, 101)
        for scope in ("strict", "subject")
    ]
    strict = [row for row in sweep if row["scope"] == "strict"]
    selected = max(
        strict,
        key=lambda row: (
            row["f1"],
            -(row["fpr"] if row["fpr"] is not None else 1.0),
            row["tpr"] if row["tpr"] is not None else 0.0,
            row["threshold"],
        ),
    )
    configured = int(policy["threshold"])
    if configured != selected["threshold"]:
        raise SystemExit(
            f"Frozen threshold {configured} does not match calibration selection "
            f"{selected['threshold']}."
        )
    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(args.output / "trial_score_summary.csv", trials)
    write_csv(args.output / "threshold_sweep.csv", sweep)
    decision = {
        "policy_version": policy["version"],
        "calibration_trials": len(trials),
        "selected_threshold": selected["threshold"],
        "selection_rule": policy["selection_rule"],
        "strict_metrics": selected,
        "subject_metrics": next(
            row for row in sweep
            if row["scope"] == "subject" and row["threshold"] == selected["threshold"]
        ),
        "held_out_data_used": False,
    }
    with (args.output / "calibration_decision.json").open(
        "w", encoding="utf-8"
    ) as stream:
        json.dump(decision, stream, indent=2)
        stream.write("\n")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
