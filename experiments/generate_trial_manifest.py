#!/usr/bin/env python3
"""Generate a deterministic, stratified CS2 evaluation trial manifest."""
import argparse
import csv
import json
import random
from pathlib import Path

BENIGN = [
    ("task_manager", "Windows Task Manager", "process_monitor"),
    ("resource_monitor", "Windows Resource Monitor", "process_monitor"),
    ("process_explorer", "Microsoft Process Explorer", "process_monitor"),
    ("process_monitor", "Microsoft Process Monitor", "diagnostic_monitor"),
    ("obs_game_capture", "OBS Studio (Game Capture)", "screen_capture"),
    ("steam_overlay", "Steam Overlay", "game_overlay"),
    ("discord_overlay", "Discord Overlay", "game_overlay"),
    ("nvidia_performance_overlay", "NVIDIA Performance Overlay", "performance_overlay"),
]
CORE_CHEATS = [
    ("fully_external_cs2", "FullyExternalCS2", "user_mode_external", "ready"),
    ("cs2_webradar", "CS2 WebRadar", "user_mode_external", "ready"),
    ("cs2_external_cheat", "CS2 External Cheat (C#)", "user_mode_external", "dependencies_required"),
    ("cs2_external_esp", "CS2 External ESP (C++)", "user_mode_external", "dependencies_required"),
]
EXTENSION_CHEATS = [
    ("valthrun_cs2", "Valthrun CS2", "kernel_external", "driver_required"),
]
FIELDS = [
    "execution_order", "trial_id", "condition", "application_name",
    "application_category", "cheat_enabled", "enabled_feature", "repetition",
    "evaluation_split", "expected_label", "duration_seconds", "interval_ms",
    "expected_scans", "sample_scope", "readiness", "notes",
]


def make_trial(key, name, category, repetition, expected_label,
               scope="user_mode", readiness="ready", split=None):
    is_cheat = expected_label == "cheat"
    return {
        "execution_order": 0,
        "trial_id": f"{'cheat' if is_cheat else 'benign'}_{key}_{repetition:02d}",
        "condition": "cheat_software" if is_cheat else (
            "baseline" if key == "baseline" else "benign_application"),
        "application_name": name,
        "application_category": category,
        "cheat_enabled": is_cheat,
        "enabled_feature": "software_active" if is_cheat else "none",
        "repetition": repetition,
        "evaluation_split": split or ("calibration" if repetition == 1 else "test"),
        "expected_label": expected_label,
        "duration_seconds": 300,
        "interval_ms": 1000,
        "expected_scans": 300,
        "sample_scope": scope,
        "readiness": readiness,
        "notes": "",
    }


def build_trials(include_extension):
    trials = [
        make_trial("baseline", "None", "baseline", repetition, "benign")
        for repetition in range(1, 6)
    ]
    for key, name, category in BENIGN:
        trials += [
            make_trial(key, name, category, repetition, "benign")
            for repetition in range(1, 6)
        ]
    for key, name, scope, readiness in CORE_CHEATS:
        trials += [
            make_trial(key, name, "cheat_sample", repetition, "cheat",
                       scope, readiness)
            for repetition in range(1, 6)
        ]
    if include_extension:
        for key, name, scope, readiness in EXTENSION_CHEATS:
            trials += [
                make_trial(key, name, "cheat_sample", repetition, "cheat",
                           scope, readiness, "extension")
                for repetition in range(1, 6)
            ]
    return trials


def write_metadata(path, trial):
    metadata = {
        "trial_id": trial["trial_id"],
        "condition": trial["condition"],
        "application_name": trial["application_name"],
        "application_category": trial["application_category"],
        "cheat_enabled": trial["cheat_enabled"],
        "enabled_feature": trial["enabled_feature"],
        "application_start_time_utc": None,
        "feature_enable_time_utc": None,
        "trial_start_time_utc": "2000-01-01T00:00:00Z",
        "trial_end_time_utc": None,
        "expected_label": trial["expected_label"],
        "notes": (
            f"split={trial['evaluation_split']}; scope={trial['sample_scope']}; "
            f"readiness={trial['readiness']}"
        ),
    }
    path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).parent / "generated")
    parser.add_argument("--seed", type=int, default=20260826)
    parser.add_argument("--include-extension", action="store_true")
    args = parser.parse_args()
    trials = build_trials(args.include_extension)
    random.Random(args.seed).shuffle(trials)
    for order, trial in enumerate(trials, 1):
        trial["execution_order"] = order
    args.output.mkdir(parents=True, exist_ok=True)
    metadata_dir = args.output / "trials"
    metadata_dir.mkdir(exist_ok=True)
    with (args.output / "trial_manifest.csv").open(
            "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(trials)
    summary = {
        "seed": args.seed,
        "total_trials": len(trials),
        "evaluation_trials": sum(
            t["evaluation_split"] in {"calibration", "test"} for t in trials),
        "calibration_trials": sum(t["evaluation_split"] == "calibration" for t in trials),
        "test_trials": sum(t["evaluation_split"] == "test" for t in trials),
        "extension_trials": sum(t["evaluation_split"] == "extension" for t in trials),
        "expected_scans": sum(t["expected_scans"] for t in trials),
    }
    (args.output / "manifest_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    for trial in trials:
        write_metadata(metadata_dir / f"{trial['trial_id']}.json", trial)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
