#!/usr/bin/env python3
"""Compute trial-level CS2 handle-detector metrics from labelled run directories."""
from __future__ import annotations
import argparse, csv, json, math
from datetime import datetime, timezone
from pathlib import Path

METHODS = ("baseline_a_any_handle", "baseline_b_vm_read", "baseline_c_memory_access", "proposed")

def keymap(obj):
    return {str(k).replace("_", "").lower(): v for k, v in obj.items()}

def value(obj, name, default=None):
    return keymap(obj).get(name.replace("_", "").lower(), default)

def truth(meta):
    label = str(value(meta, "expected_label", "") or "").lower()
    if label in ("benign", "cheat"):
        return label
    enabled = value(meta, "cheat_enabled")
    return "cheat" if enabled is True else "benign" if enabled is False else "unknown"

def evaluation_split(meta):
    direct = str(value(meta, "evaluation_split", "") or "").strip().lower()
    if direct:
        return direct
    for part in str(value(meta, "notes", "") or "").split(";"):
        key, separator, split_value = part.strip().partition("=")
        if separator and key.strip().lower() == "split":
            return split_value.strip().lower()
    return "unknown"

def parse_time(text):
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None

def is_true(text):
    return str(text).strip().lower() in ("1", "true", "yes")

def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))

def method_flags(row, threshold):
    rights = (row.get("AccessRights") or "").upper()
    return {
        "baseline_a_any_handle": True,
        "baseline_b_vm_read": "VM_READ" in rights,
        "baseline_c_memory_access": any(x in rights for x in ("VM_READ", "VM_WRITE", "VM_OPERATION")),
        "proposed": is_true(row.get("AlertStatus")) or
                    int(row.get("AdjustedRiskScore") or row.get("RiskScore") or 0) >= threshold,
    }

def is_subject_row(row, meta):
    application_pids = value(meta, "application_pids")
    if isinstance(application_pids, list) and application_pids:
        return str(row.get("SourceProcessId") or "") in {str(pid) for pid in application_pids}

    application_pid = value(meta, "application_pid")
    if application_pid not in (None, ""):
        return str(row.get("SourceProcessId") or "") == str(application_pid)
    application_path = str(value(meta, "application_path", "") or "").strip()
    if application_path:
        return str(row.get("SourceImagePath") or "").casefold() == application_path.casefold()
    return None

def evaluate_trial(run_dir, meta):
    handles = read_csv(run_dir / "handles.csv")
    threshold = int(value(meta, "detection_threshold", 60) or 60)
    flags = {method: False for method in METHODS}
    first = {method: None for method in METHODS}
    subject_flags = {method: False for method in METHODS}
    subject_first = {method: None for method in METHODS}

    background_flags = {method: False for method in METHODS}
    subject_handle_count = 0
    label = truth(meta)
    reference = (
        parse_time(value(meta, "feature_enable_time_utc")) or
        parse_time(value(meta, "application_start_time_utc")) or
        parse_time(value(meta, "trial_start_time_utc"))
    )
    latency_reference = reference if label == "cheat" else (
        parse_time(value(meta, "trial_start_time_utc")) or reference
    )
    application_pids = value(meta, "application_pids")
    has_subject_identity = (
        (isinstance(application_pids, list) and bool(application_pids)) or
        value(meta, "application_pid") not in (None, "") or
        bool(str(value(meta, "application_path", "") or "").strip())
    )

    for row in handles:
        timestamp = parse_time(row.get("TimestampUtc"))
        row_flags = method_flags(row, threshold)
        after_activation = reference is None or timestamp is None or timestamp >= reference
        subject_match = is_subject_row(row, meta)
        subject_match = after_activation if subject_match is None else after_activation and subject_match
        if subject_match:
            subject_handle_count += 1
        eligible = label != "cheat" or subject_match
        for method, detected in row_flags.items():
            if detected and subject_match:
                subject_flags[method] = True
                if timestamp and (subject_first[method] is None or timestamp < subject_first[method]):
                    subject_first[method] = timestamp
            if detected and eligible:
                flags[method] = True
                if timestamp and (first[method] is None or timestamp < first[method]):
                    first[method] = timestamp
            if detected and label == "cheat" and not subject_match:
                background_flags[method] = True
    scan_rows = read_csv(run_dir / "scan_summary.csv")
    numbers = {row.get("ScanNumber") for row in scan_rows if row.get("ScanNumber")}
    scans = len(numbers) if numbers else len(scan_rows)
    result = {
        "trial_id": value(meta, "trial_id", run_dir.name),
        "condition": value(meta, "condition", ""),
        "application_name": value(meta, "application_name", ""),
        "enabled_feature": value(meta, "enabled_feature", ""),
        "expected_label": label,
        "evaluation_split": evaluation_split(meta),
        "scan_count": scans,
        "attribution_mode": "source_identity" if has_subject_identity else "activation_window",
        "subject_handle_count": subject_handle_count,
    }
    for method in METHODS:
        result[method] = int(flags[method])
        result[method + "_latency_ms"] = (
            round((first[method] - latency_reference).total_seconds() * 1000, 3)
            if first[method] and latency_reference else ""
        )
        result["background_" + method] = int(background_flags[method]) if label == "cheat" else ""
        result["subject_" + method] = int(subject_flags[method])
        result["subject_" + method + "_latency_ms"] = (
            round((subject_first[method] - reference).total_seconds() * 1000, 3)
            if subject_first[method] and reference else ""
        )
    return result

def wilson(successes, total):
    if not total:
        return ("", "")
    z = 1.959963984540054
    p = successes / total
    den = 1 + z*z/total
    center = (p + z*z/(2*total)) / den
    margin = z * math.sqrt((p*(1-p) + z*z/(4*total))/total) / den
    return (max(0, center-margin), min(1, center+margin))

def summarize(trials, method):
    labelled = [row for row in trials if row["expected_label"] in ("benign", "cheat")]
    tp = sum(row["expected_label"] == "cheat" and row[method] for row in labelled)
    fn = sum(row["expected_label"] == "cheat" and not row[method] for row in labelled)
    fp = sum(row["expected_label"] == "benign" and row[method] for row in labelled)
    tn = sum(row["expected_label"] == "benign" and not row[method] for row in labelled)
    recall = tp/(tp+fn) if tp+fn else None
    fpr = fp/(fp+tn) if fp+tn else None
    precision = tp/(tp+fp) if tp+fp else None
    f1 = 2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else None
    tpr_ci = wilson(tp, tp+fn)
    fpr_ci = wilson(fp, fp+tn)
    return {
        "method": method, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "tpr": recall, "fnr": 1-recall if recall is not None else None,
        "fpr": fpr, "precision": precision, "f1": f1,
        "tpr_ci95_low": tpr_ci[0], "tpr_ci95_high": tpr_ci[1],
        "fpr_ci95_low": fpr_ci[0], "fpr_ci95_high": fpr_ci[1],
    }

def write_rows(path, rows):
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("data_root", type=Path)
    parser.add_argument("--output", type=Path, default=Path("analysis_output"))
    parser.add_argument(
        "--split",
        choices=("test", "calibration", "extension", "all"),
        default="test",
        help="Evaluate held-out test trials by default; analyse coverage separately.",
    )
    args = parser.parse_args()
    trials = []
    for metadata_path in args.data_root.rglob("metadata.json"):
        run_dir = metadata_path.parent
        if not (run_dir / "handles.csv").exists():
            continue
        with metadata_path.open("r", encoding="utf-8-sig") as stream:
            trials.append(evaluate_trial(run_dir, json.load(stream)))
    if args.split != "all":
        trials = [
            trial for trial in trials
            if trial["evaluation_split"] == args.split
        ]
    if not trials:
        raise SystemExit(
            f"No labelled handle-monitor runs matched split={args.split!r}. "
            "Generated trial metadata stores the split in notes."
        )
    args.output.mkdir(parents=True, exist_ok=True)
    write_rows(args.output / "trial_results.csv", trials)
    write_rows(args.output / "method_summary.csv", [summarize(trials, method) for method in METHODS])
    print(f"Analysed {len(trials)} trials; results written to {args.output.resolve()}")

if __name__ == "__main__":
    main()
