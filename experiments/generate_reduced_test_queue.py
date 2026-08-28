#!/usr/bin/env python3
"""Create the balanced 39-trial plan: 13 calibration plus repetitions 2 and 3."""
import argparse
import csv
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).parent / "generated" / "trial_manifest.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parent / "generated" / "reduced_trial_queue.csv",
    )
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    selected = [
        row for row in rows
        if row["evaluation_split"] == "test" and int(row["repetition"]) in (2, 3)
    ]
    selected.sort(key=lambda row: int(row["execution_order"]))
    metadata_dir = args.output.parent / "reduced_trials"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    queue = []
    for reduced_order, row in enumerate(selected, 1):
        item = dict(row)
        item["reduced_execution_order"] = reduced_order
        item["frozen_threshold"] = 45
        item["policy_version"] = "calibration-v1"
        source_metadata = args.manifest.parent / "trials" / f"{item['trial_id']}.json"
        with source_metadata.open("r", encoding="utf-8-sig") as stream:
            metadata = json.load(stream)
        metadata["detection_threshold"] = 45
        metadata["policy_version"] = "calibration-v1"
        metadata["notes"] = (
            metadata.get("notes", "") + "; design=balanced_reduced"
        )
        target_metadata = metadata_dir / f"{item['trial_id']}.json"
        with target_metadata.open("w", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2)
            stream.write("\n")
        item["trial_metadata_path"] = target_metadata.as_posix()
        queue.append(item)
    fields = [
        "reduced_execution_order",
        "execution_order",
        "trial_id",
        "condition",
        "application_name",
        "application_category",
        "cheat_enabled",
        "enabled_feature",
        "repetition",
        "evaluation_split",
        "expected_label",
        "duration_seconds",
        "interval_ms",
        "expected_scans",
        "sample_scope",
        "readiness",
        "frozen_threshold",
        "policy_version",
        "notes",
        "trial_metadata_path",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(queue)
    conditions = sorted({row["application_name"] for row in queue})
    summary = {
        "design": "balanced_reduced",
        "policy_version": "calibration-v1",
        "frozen_threshold": 45,
        "completed_calibration_trials": 13,
        "remaining_test_trials": len(queue),
        "final_independent_trials": 13 + len(queue),
        "remaining_expected_scans": sum(int(row["expected_scans"]) for row in queue),
        "final_expected_scans": 13 * 300 + sum(int(row["expected_scans"]) for row in queue),
        "repetitions_per_condition": 3,
        "selected_test_repetitions": [2, 3],
        "condition_count": len(conditions),
        "conditions": conditions,
    }
    summary_path = args.output.with_name("reduced_manifest_summary.json")
    with summary_path.open("w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
