# CS2 Anti-cheating Research

The current phase establishes reproducible baselines for normal and test CS2 behavior. `CS2BaselineLogger` only observes processes and does not modify the target process.

## Build

```powershell
dotnet build Anti_cheating.sln
```

## Capture an Experiment

```powershell
dotnet run --project CS2BaselineLogger -- `
  --experiment baseline_dust2_01 `
  --cheat false `
  --map de_dust2 `
  --mode competitive `
  --bots 9 `
  --duration-seconds 600
```

If multiple `cs2.exe` processes exist, the program prompts you to select a PID. You can also specify one directly with `--pid 1234`. Run with `--help` to see all options.

Each run creates a unique directory containing:

- `metadata.json`: experiment conditions and host information;
- `metrics.csv`: time-series data for CPU, memory, threads, handle count, module count, and other metrics;
- `modules.csv`: periodically captured module names, paths, base addresses, sizes, and versions.

## Experiment Protocol

Before starting a set of controlled experiments, keep the following fixed:

1. CS2, server, and test program versions;
2. map, mode, bot count, and bot difficulty;
3. resolution, graphics quality, FPS cap, and background programs;
4. warm-up time and capture duration for each experiment;
5. multiple repetitions of each experiment type, with separate records retained for each label.

FPS is not yet included in the current collector. Module loads and handle counts are only risk signals and cannot independently prove cheating.

## External Handle Monitoring

`CS2HandleMonitor` enumerates external process handles that reference CS2 and records the source process, image path, `GrantedAccess`, interpreted permissions, and an initial risk score. Run it in an administrator PowerShell session to improve handle visibility:

```powershell
dotnet run --project CS2HandleMonitor -- `
  --process cs2 `
  --interval-seconds 2 `
  --duration-seconds 600
```

When `--pid` is omitted, the monitor automatically discovers and monitors every `cs2.exe` process during each scan. It classifies targets as `Client`, `HeadlessOrServer`, or `ServerOrOther` based on their window titles. To monitor one fixed experiment target, pass `--pid` explicitly.

Output is written to a unique `data/handle_monitor_*` directory. `handles.csv` stores matching external-handle snapshots, `scan_summary.csv` stores completeness statistics for each scan, `handle_events.csv` stores `Opened`/`Closed` lifecycle events and durations, and `detections.csv` stores new alerts that exceed the detection threshold. Calibration froze the default threshold at `45`; the versioned policy in `CS2HandleMonitor/frozen_detection_policy.json` also caps two exact, signed calibration false-positive SHA-256 identities at risk 5. Do not extend that allowlist from held-out results. Source-process identity includes the parent PID, start time, SHA-256 hash, and embedded signing-certificate subject. `HasEmbeddedSignature` only indicates that the file contains a certificate; it does not mean the certificate chain has been validated as trusted. Handles owned by the target process itself are excluded. The tool only reads and duplicates handles for identification; it does not close external handles or modify the target process. Legitimate overlays, recording software, driver utilities, and accessibility software may also use `VM_READ`, so findings must be evaluated together with signatures, paths, duration, and other behavior.

## Labelled Evaluation Trials

Create one JSON file per independent trial from `experiments/trial-template.json`. Ground truth comes from this file, never from the detector score. Run a five-minute trial at a one-second interval with:

```powershell
dotnet run --project CS2HandleMonitor -- `
  --pid 1234 `
  --interval-seconds 1 `
  --duration-seconds 300 `
  --threshold 45 `
  --trial-metadata experiments/trials/benign_task_manager_01.json
```

The copied `metadata.json` and every CSV contain the stable `trial_id`. Scan summaries also record scan duration and monitor CPU, working-set, and private-memory use. After collecting multiple labelled trials, compare the three simple baselines with the proposed threshold using:

```powershell
python analysis/evaluate_trials.py data --output analysis_output
```

The analyser reports trial-level TP, FP, TN, FN, TPR, FPR, FNR, precision, F1, Wilson 95% confidence intervals, and detection latency. Continuous scans are counted only as temporal observations, not as independent samples.


## Reproducible Trial Manifest

Run `python experiments/generate_trial_manifest.py` to generate the randomized full 65-trial manifest. It contains 13 calibration and 52 held-out test trials. Add five optional Valthrun kernel-coverage trials with `--include-extension`.

The time-constrained balanced design retains repetitions 1¨C3 for every condition: 13 completed calibration trials plus 26 held-out trials, for 39 independent trials and approximately 11,700 scans. Generate its frozen queue and verify the calibration decision with:

```powershell
python analysis/calibrate_threshold.py data
python experiments/generate_reduced_test_queue.py
```

The reduced queue is written to `experiments/generated/reduced_trial_queue.csv`; its 26 metadata files record `detection_threshold=45` and `policy_version=calibration-v1`. The analyser reports the held-out test split by default. Use `--split calibration`, `--split extension`, or `--split all` explicitly for secondary analyses. Kernel-extension results must not be merged into the user-mode detector TPR/FNR.
