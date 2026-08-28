#!/usr/bin/env python3
"""Generate the frozen held-out report and its SHA-256 artifact manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def as_int(value: str | int | None) -> int:
    return int(float(value or 0))


def as_float(value: str | float | None) -> float | None:
    if value in (None, ""):
        return None
    return float(value)


def fmt(value: float | None, digits: int = 3) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def percentile_nearest_rank(values: Iterable[float], percentile: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total == 0:
        return 0.0, 1.0
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    ) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def parse_note_number(notes: str, key: str) -> float | None:
    match = re.search(rf"(?:^|;\s*){re.escape(key)}=([-+]?\d+(?:\.\d+)?)", notes)
    return float(match.group(1)) if match else None


def markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def find_output_directory(trial_id: str) -> Path:
    candidates = []
    for path in (ROOT / "data").glob(f"{trial_id}_*"):
        metadata_path = path / "metadata.json"
        if not metadata_path.exists():
            continue
        metadata = read_json(metadata_path)
        if metadata.get("trial_id") == trial_id and metadata.get("trial_end_time_utc"):
            candidates.append(path)
    if len(candidates) != 1:
        raise RuntimeError(
            f"Expected one completed data directory for {trial_id}, found {len(candidates)}"
        )
    return candidates[0]


def confusion(rows: list[dict[str, str]]) -> dict[str, int | float]:
    tp = sum(row["expected_label"] == "cheat" and as_int(row["proposed"]) == 1 for row in rows)
    fp = sum(row["expected_label"] == "benign" and as_int(row["proposed"]) == 1 for row in rows)
    tn = sum(row["expected_label"] == "benign" and as_int(row["proposed"]) == 0 for row in rows)
    fn = sum(row["expected_label"] == "cheat" and as_int(row["proposed"]) == 0 for row in rows)
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "tpr": tpr, "fpr": fpr, "precision": precision, "f1": f1}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "analysis_output" / "held_out")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    queue_path = ROOT / "experiments" / "generated" / "reduced_trial_queue.csv"
    metadata_root = ROOT / "experiments" / "generated" / "reduced_trials"
    results_path = ROOT / "analysis_output" / "held_out" / "trial_results.csv"
    methods_path = ROOT / "analysis_output" / "held_out" / "method_summary.csv"
    policy_path = ROOT / "CS2HandleMonitor" / "frozen_detection_policy.json"
    decision_path = ROOT / "analysis_output" / "calibration" / "calibration_decision.json"
    report_path = output_dir / "held_out_final_report.md"
    manifest_path = output_dir / "artifact_manifest.sha256.csv"

    queue = sorted(read_csv(queue_path), key=lambda row: as_int(row["reduced_execution_order"]))
    results = read_csv(results_path)
    methods = read_csv(methods_path)
    policy = read_json(policy_path)
    decision = read_json(decision_path)

    if len(queue) != 26 or len(results) != 26 or len({row["trial_id"] for row in results}) != 26:
        raise RuntimeError("Held-out inputs are not the expected 26 unique trials")
    if decision.get("held_out_data_used") is not False:
        raise RuntimeError("Calibration decision does not explicitly state held_out_data_used=false")
    if policy.get("version") != "calibration-v1" or policy.get("threshold") != 45:
        raise RuntimeError("Frozen policy version or threshold changed")

    result_by_id = {row["trial_id"]: row for row in results}
    metadata_by_id: dict[str, dict] = {}
    output_by_id: dict[str, Path] = {}
    scan_rows: list[dict[str, str]] = []
    artifact_paths: set[Path] = {
        Path(__file__).resolve(),
        queue_path,
        results_path,
        methods_path,
        policy_path,
        decision_path,
        report_path,
    }

    for queue_row in queue:
        trial_id = queue_row["trial_id"]
        if trial_id not in result_by_id:
            raise RuntimeError(f"Missing analysis result for {trial_id}")
        metadata_path = metadata_root / f"{trial_id}.json"
        metadata = read_json(metadata_path)
        required = ("trial_start_time_utc", "trial_end_time_utc", "observed_results", "performance")
        if any(not metadata.get(key) for key in required):
            raise RuntimeError(f"Incomplete source metadata for {trial_id}")
        data_dir = find_output_directory(trial_id)
        metadata_by_id[trial_id] = metadata
        output_by_id[trial_id] = data_dir
        artifact_paths.add(metadata_path)
        artifact_paths.update(path for path in data_dir.rglob("*") if path.is_file())
        scan_rows.extend(read_csv(data_dir / "scan_summary.csv"))

    proposed = next(row for row in methods if row["method"] == "proposed")
    total_scans = sum(as_int(row["scan_count"]) for row in results)
    cheat_count = sum(row["expected_label"] == "cheat" for row in results)
    benign_count = len(results) - cheat_count
    detection_latencies = [
        value
        for row in results
        if row["expected_label"] == "cheat"
        for value in [as_float(row["proposed_latency_ms"])]
        if value is not None
    ]
    scan_durations = [value for row in scan_rows for value in [as_float(row.get("ScanDurationMs"))] if value is not None]
    cpu_values = [value for row in scan_rows for value in [as_float(row.get("MonitorCpuPercent"))] if value is not None]
    working_sets = [value for row in scan_rows for value in [as_float(row.get("MonitorWorkingSetMb"))] if value is not None]

    sensitivity_rows = [row for row in results if row["trial_id"] != "cheat_fully_external_cs2_02"]
    sensitivity = confusion(sensitivity_rows)
    sensitivity_tpr_ci = wilson_interval(int(sensitivity["tp"]), int(sensitivity["tp"] + sensitivity["fn"]))
    sensitivity_fpr_ci = wilson_interval(int(sensitivity["fp"]), int(sensitivity["fp"] + sensitivity["tn"]))

    deviations: list[tuple[str, str]] = []
    for queue_row in queue:
        trial_id = queue_row["trial_id"]
        notes = metadata_by_id[trial_id].get("notes", "")
        stable = parse_note_number(notes, "stable_window_seconds")
        active = parse_note_number(notes, "active_window_seconds")
        if active is None:
            active = parse_note_number(notes, "confirmed_active_window_seconds")
        descriptions = []
        if "user_requested_frontend=true" in notes:
            descriptions.append("WebRadar frontend was started by explicit user request although calibration used frontend=false")
            if "frontend cold start delayed" in notes and active is not None:
                descriptions.append(f"frontend cold start reduced the activity window to {active:.3f}s")
        if "unexpected_delayed_duplicate_monitor" in notes:
            descriptions.append("an unintended delayed monitor overlapped this trial; preserved as an operational protocol deviation")
        if "overlay_ui_activation_not_independently_verified=true" in notes:
            descriptions.append("overlay helper processes were observed, but overlay UI activation was not independently verified")
        if (
            metadata_by_id[trial_id].get("application_process", {}).get("recording_stop_log_confirmed") is False
            or "stop log not confirmed" in notes.lower()
            or "stop_log_not_confirmed" in notes.lower()
            or "lacked obs log confirmation" in notes.lower()
        ):
            descriptions.append("recording stop was not independently confirmed in the application log")
        if "timing deviation" in notes.lower():
            activation_match = re.search(r"activation at elapsed (\d+(?:\.\d+)?)s", notes, re.IGNORECASE)
            activation = float(activation_match.group(1)) if activation_match else stable
            descriptions.append(
                "manual confirmation delayed feature activation"
                + (f" to {activation:.3f}s elapsed" if activation is not None else "")
                + (f", leaving {active:.3f}s active" if active is not None else "")
            )
        if "uac_delay_recorded_in_stable_window=true" in notes:
            descriptions.append(
                "Windows UAC approval delayed application activation"
                + (f"; stable/activity windows were {stable:.3f}s/{active:.3f}s" if stable is not None and active is not None else "")
            )
        if stable is not None and (stable > 120 or active is not None and active < 180):
            descriptions.append(f"manual/startup delay changed the stable/activity windows to {stable:.3f}s/{active:.3f}s")
        if descriptions:
            deviations.append((trial_id, "; ".join(descriptions)))

    completed_at = max(
        datetime.fromisoformat(metadata["trial_end_time_utc"].replace("Z", "+00:00"))
        for metadata in metadata_by_id.values()
    )
    generated_at = completed_at

    lines = [
        "# Anti-cheating balanced-reduction held-out report",
        "",
        f"Data-derived report timestamp: {generated_at.isoformat().replace('+00:00', 'Z')}",
        f"Experiment completion: {completed_at.isoformat().replace('+00:00', 'Z')}",
        "",
        "## Executive summary",
        "",
        f"The frozen `calibration-v1` policy was evaluated on {len(results)} held-out trials "
        f"({cheat_count} cheat, {benign_count} benign) comprising {total_scans:,} scans. "
        "Held-out data were not used to choose the threshold or extend the trusted-process list.",
        "",
        f"At threshold {policy['threshold']}, the proposed method produced TP={proposed['tp']}, "
        f"FP={proposed['fp']}, TN={proposed['tn']}, and FN={proposed['fn']} "
        f"(TPR={float(proposed['tpr']):.3f}, FPR={float(proposed['fpr']):.3f}, F1={float(proposed['f1']):.3f}). "
        "These results describe this finite test set and do not establish zero deployment error.",
        "",
        "## Frozen policy and separation of data",
        "",
        "| Item | Frozen value |",
        "|---|---:|",
        f"| Policy version | `{policy['version']}` |",
        f"| Detection threshold | {policy['threshold']} |",
        f"| Calibration trials | {decision['calibration_trials']} |",
        f"| Held-out trials | {len(results)} |",
        f"| Trusted exact SHA-256 entries | {len(policy['trusted_process_sha256'])} |",
        f"| Held-out data used for calibration | `{str(decision['held_out_data_used']).lower()}` |",
        "",
        "The trusted list remains version-specific, requires an embedded signature plus an exact SHA-256 match, "
        "and was not expanded after inspecting held-out results.",
        "",
        "## Trial-level method results",
        "",
        "Wilson score intervals are two-sided 95% intervals.",
        "",
        "| Method | TP | FP | TN | FN | TPR (95% CI) | FPR (95% CI) | Precision | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in methods:
        lines.append(
            f"| {markdown_escape(row['method'])} | {row['tp']} | {row['fp']} | {row['tn']} | {row['fn']} | "
            f"{float(row['tpr']):.3f} ({float(row['tpr_ci95_low']):.3f}–{float(row['tpr_ci95_high']):.3f}) | "
            f"{float(row['fpr']):.3f} ({float(row['fpr_ci95_low']):.3f}–{float(row['fpr_ci95_high']):.3f}) | "
            f"{float(row['precision']):.3f} | {float(row['f1']):.3f} |"
        )

    lines.extend([
        "",
        "## Detection latency and monitor performance",
        "",
        "Latency is measured from recorded application activation to the first proposed-method detection. "
        "P95 values use the nearest-rank definition.",
        "",
        "| Measure | N | Mean | Median | P95 | Maximum |",
        "|---|---:|---:|---:|---:|---:|",
        f"| Proposed detection latency (ms) | {len(detection_latencies)} | {fmt(statistics.fmean(detection_latencies))} | "
        f"{fmt(statistics.median(detection_latencies))} | {fmt(percentile_nearest_rank(detection_latencies, 0.95))} | {fmt(max(detection_latencies))} |",
        f"| Scan duration (ms) | {len(scan_durations)} | {fmt(statistics.fmean(scan_durations))} | "
        f"{fmt(statistics.median(scan_durations))} | {fmt(percentile_nearest_rank(scan_durations, 0.95))} | {fmt(max(scan_durations))} |",
        f"| Monitor CPU (%) | {len(cpu_values)} | {fmt(statistics.fmean(cpu_values))} | "
        f"{fmt(statistics.median(cpu_values))} | {fmt(percentile_nearest_rank(cpu_values, 0.95))} | {fmt(max(cpu_values))} |",
        f"| Monitor working set (MiB) | {len(working_sets)} | {fmt(statistics.fmean(working_sets))} | "
        f"{fmt(statistics.median(working_sets))} | {fmt(percentile_nearest_rank(working_sets, 0.95))} | {fmt(max(working_sets))} |",
        "",
        "## Per-trial results",
        "",
        "| Order | Trial | Label | Scans | Proposed | Latency (ms) | Subject handles | App handles | Max app risk | Mean scan (ms) |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for queue_row in queue:
        trial_id = queue_row["trial_id"]
        result = result_by_id[trial_id]
        metadata = metadata_by_id[trial_id]
        observed = metadata["observed_results"]
        performance = metadata["performance"]
        lines.append(
            f"| {queue_row['reduced_execution_order']} | `{trial_id}` | {result['expected_label']} | "
            f"{result['scan_count']} | {result['proposed']} | {fmt(as_float(result['proposed_latency_ms']))} | "
            f"{result['subject_handle_count']} | {observed.get('application_handle_rows', 0)} | "
            f"{fmt(as_float(observed.get('application_max_adjusted_risk_score')))} | "
            f"{fmt(as_float(performance.get('scan_duration_ms_mean')))} |"
        )

    lines.extend([
        "",
        "## Operational deviations and sensitivity",
        "",
        "The following deviations were retained in metadata rather than silently removed or rerun:",
        "",
        "| Trial | Recorded deviation |",
        "|---|---|",
    ])
    for trial_id, description in deviations:
        lines.append(f"| `{trial_id}` | {markdown_escape(description)} |")
    lines.extend([
        "",
        "Two invalid duplicate-startup artifacts were preserved outside the analysis input under "
        "`experiments/aborted_runs`; neither contributes a row to `trial_results.csv`.",
        "",
        "As a read-only operational sensitivity check, excluding `cheat_fully_external_cs2_02` "
        "(the valid trial that overlapped an unintended delayed monitor) gives:",
        "",
        "| TP | FP | TN | FN | TPR (95% CI) | FPR (95% CI) | Precision | F1 |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {sensitivity['tp']} | {sensitivity['fp']} | {sensitivity['tn']} | {sensitivity['fn']} | "
        f"{sensitivity['tpr']:.3f} ({sensitivity_tpr_ci[0]:.3f}–{sensitivity_tpr_ci[1]:.3f}) | "
        f"{sensitivity['fpr']:.3f} ({sensitivity_fpr_ci[0]:.3f}–{sensitivity_fpr_ci[1]:.3f}) | "
        f"{sensitivity['precision']:.3f} | {sensitivity['f1']:.3f} |",
        "",
        "This sensitivity result is descriptive only and was not used to alter the threshold, scoring, or trusted list.",
        "",
        "## Limitations and validity threats",
        "",
        "- The held-out set contains only 8 cheat and 18 benign trials; the confidence intervals remain materially wider than the point estimates.",
        "- Trials were collected on one host and software-version snapshot. Exact-hash allowlisting is intentionally version-specific.",
        "- Several overlays required manual confirmation, creating variable stable and active windows.",
        "- WebRadar frontend execution differed from calibration by explicit user request and is disclosed above.",
        "- One valid cheat trial experienced concurrent monitoring overhead from a delayed duplicate launcher; both the deviation and sensitivity result are retained.",
        "- The tested samples do not cover kernel-mode, DMA, injected, or novel access strategies beyond the stated experiment scope.",
        "",
        "## Reproducibility artifacts",
        "",
        "- `trial_results.csv`: per-trial decisions and latencies.",
        "- `method_summary.csv`: final confusion matrices and Wilson intervals.",
        "- `artifact_manifest.sha256.csv`: relative path, byte length, and SHA-256 for the report generator, report, frozen inputs, 26 source metadata files, 26 completed raw-data directories, and final analysis CSVs.",
        "- Invalid duplicate-startup directories are preserved under `experiments/aborted_runs` but deliberately excluded from the held-out manifest and metrics.",
        "",
        "No policy selection or trusted-list mutation is performed by this report generator.",
        "",
    ])
    report_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")

    rows = []
    for path in sorted(artifact_paths, key=lambda item: item.relative_to(ROOT).as_posix().lower()):
        if not path.exists() or not path.is_file():
            raise RuntimeError(f"Manifest artifact missing: {path}")
        rows.append({
            "relative_path": path.relative_to(ROOT).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        })
    with manifest_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("relative_path", "size_bytes", "sha256"))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {report_path}")
    print(f"Wrote {manifest_path} with {len(rows)} artifacts")


if __name__ == "__main__":
    main()
