# Anti-cheating balanced-reduction held-out report

Data-derived report timestamp: 2026-08-27T23:09:57.299951Z
Experiment completion: 2026-08-27T23:09:57.299951Z

## Executive summary

The frozen `calibration-v1` policy was evaluated on 26 held-out trials (8 cheat, 18 benign) comprising 7,818 scans. Held-out data were not used to choose the threshold or extend the trusted-process list.

At threshold 45, the proposed method produced TP=8, FP=0, TN=18, and FN=0 (TPR=1.000, FPR=0.000, F1=1.000). These results describe this finite test set and do not establish zero deployment error.

## Frozen policy and separation of data

| Item | Frozen value |
|---|---:|
| Policy version | `calibration-v1` |
| Detection threshold | 45 |
| Calibration trials | 13 |
| Held-out trials | 26 |
| Trusted exact SHA-256 entries | 2 |
| Held-out data used for calibration | `false` |

The trusted list remains version-specific, requires an embedded signature plus an exact SHA-256 match, and was not expanded after inspecting held-out results.

## Trial-level method results

Wilson score intervals are two-sided 95% intervals.

| Method | TP | FP | TN | FN | TPR (95% CI) | FPR (95% CI) | Precision | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline_a_any_handle | 8 | 18 | 0 | 0 | 1.000 (0.676–1.000) | 1.000 (0.824–1.000) | 0.308 | 0.471 |
| baseline_b_vm_read | 8 | 18 | 0 | 0 | 1.000 (0.676–1.000) | 1.000 (0.824–1.000) | 0.308 | 0.471 |
| baseline_c_memory_access | 8 | 18 | 0 | 0 | 1.000 (0.676–1.000) | 1.000 (0.824–1.000) | 0.308 | 0.471 |
| proposed | 8 | 0 | 18 | 0 | 1.000 (0.676–1.000) | 0.000 (0.000–0.176) | 1.000 | 1.000 |

## Detection latency and monitor performance

Latency is measured from recorded application activation to the first proposed-method detection. P95 values use the nearest-rank definition.

| Measure | N | Mean | Median | P95 | Maximum |
|---|---:|---:|---:|---:|---:|
| Proposed detection latency (ms) | 8 | 1858.898 | 1261.305 | 5133.160 | 5133.160 |
| Scan duration (ms) | 7818 | 427.388 | 360.209 | 718.206 | 948.322 |
| Monitor CPU (%) | 7818 | 2.947 | 2.967 | 3.195 | 3.976 |
| Monitor working set (MiB) | 7818 | 94.619 | 94.174 | 114.125 | 142.453 |

## Per-trial results

| Order | Trial | Label | Scans | Proposed | Latency (ms) | Subject handles | App handles | Max app risk | Mean scan (ms) |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | `benign_nvidia_performance_overlay_02` | benign | 301 | 0 | — | 1140 | 0 | — | 561.117 |
| 2 | `benign_baseline_02` | benign | 301 | 0 | — | 1505 | 0 | — | 391.646 |
| 3 | `cheat_fully_external_cs2_03` | cheat | 301 | 1 | 5133.160 | 1315 | 215 | 100.000 | 581.254 |
| 4 | `benign_obs_game_capture_02` | benign | 301 | 0 | — | 1000 | 0 | — | 699.228 |
| 5 | `benign_process_monitor_02` | benign | 301 | 0 | — | 1065 | 0 | — | 616.116 |
| 6 | `benign_resource_monitor_03` | benign | 300 | 0 | — | 1125 | 0 | — | 715.681 |
| 7 | `benign_discord_overlay_03` | benign | 300 | 0 | — | 1090 | 0 | — | 552.544 |
| 8 | `benign_obs_game_capture_03` | benign | 301 | 0 | — | 1090 | 0 | — | 348.902 |
| 9 | `cheat_cs2_webradar_02` | cheat | 301 | 1 | 631.513 | 918 | 153 | 45.000 | 286.887 |
| 10 | `benign_nvidia_performance_overlay_03` | benign | 300 | 0 | — | 888 | 0 | — | 362.812 |
| 11 | `cheat_cs2_webradar_03` | cheat | 301 | 1 | 417.109 | 1224 | 204 | 45.000 | 275.741 |
| 12 | `cheat_cs2_external_cheat_03` | cheat | 300 | 1 | 963.479 | 1278 | 213 | 100.000 | 335.679 |
| 13 | `benign_process_explorer_02` | benign | 300 | 0 | — | 1095 | 0 | — | 374.463 |
| 14 | `benign_process_monitor_03` | benign | 301 | 0 | — | 1100 | 0 | — | 414.386 |
| 15 | `benign_process_explorer_03` | benign | 300 | 0 | — | 1120 | 0 | — | 342.987 |
| 16 | `cheat_fully_external_cs2_02` | cheat | 300 | 1 | 3728.722 | 1203 | 198 | 100.000 | 324.768 |
| 17 | `benign_steam_overlay_02` | benign | 301 | 0 | — | 960 | 301 | 5.000 | 316.605 |
| 18 | `cheat_cs2_external_esp_03` | cheat | 301 | 1 | 1474.593 | 1122 | 187 | 60.000 | 436.070 |
| 19 | `benign_discord_overlay_02` | benign | 301 | 0 | — | 1080 | 0 | — | 301.194 |
| 20 | `cheat_cs2_external_cheat_02` | cheat | 301 | 1 | 1350.316 | 1277 | 212 | 100.000 | 417.475 |
| 21 | `benign_baseline_03` | benign | 301 | 0 | — | 1505 | 0 | — | 338.870 |
| 22 | `benign_task_manager_02` | benign | 301 | 0 | — | 1110 | 0 | — | 297.616 |
| 23 | `benign_resource_monitor_02` | benign | 301 | 0 | — | 1115 | 0 | — | 317.975 |
| 24 | `cheat_cs2_external_esp_02` | cheat | 301 | 1 | 1172.295 | 1169 | 194 | 60.000 | 513.747 |
| 25 | `benign_task_manager_03` | benign | 301 | 0 | — | 1130 | 0 | — | 565.991 |
| 26 | `benign_steam_overlay_03` | benign | 300 | 0 | — | 540 | 300 | 5.000 | 422.382 |

## Operational deviations and sensitivity

The following deviations were retained in metadata rather than silently removed or rerun:

| Trial | Recorded deviation |
|---|---|
| `benign_obs_game_capture_02` | recording stop was not independently confirmed in the application log |
| `benign_discord_overlay_03` | overlay helper processes were observed, but overlay UI activation was not independently verified |
| `cheat_cs2_webradar_02` | WebRadar frontend was started by explicit user request although calibration used frontend=false; frontend cold start reduced the activity window to 153.026s |
| `benign_nvidia_performance_overlay_03` | manual confirmation delayed feature activation to 151.268s elapsed, leaving 148.791s active |
| `cheat_cs2_webradar_03` | WebRadar frontend was started by explicit user request although calibration used frontend=false |
| `cheat_fully_external_cs2_02` | an unintended delayed monitor overlapped this trial; preserved as an operational protocol deviation |
| `benign_discord_overlay_02` | overlay helper processes were observed, but overlay UI activation was not independently verified |
| `cheat_cs2_external_esp_02` | Windows UAC approval delayed application activation; stable/activity windows were 105.909s/194.744s |
| `benign_steam_overlay_03` | manual/startup delay changed the stable/activity windows to 191.122s/108.977s |

Two invalid duplicate-startup artifacts were preserved outside the analysis input under `experiments/aborted_runs`; neither contributes a row to `trial_results.csv`.

As a read-only operational sensitivity check, excluding `cheat_fully_external_cs2_02` (the valid trial that overlapped an unintended delayed monitor) gives:

| TP | FP | TN | FN | TPR (95% CI) | FPR (95% CI) | Precision | F1 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 7 | 0 | 18 | 0 | 1.000 (0.646–1.000) | 0.000 (0.000–0.176) | 1.000 | 1.000 |

This sensitivity result is descriptive only and was not used to alter the threshold, scoring, or trusted list.

## Limitations and validity threats

- The held-out set contains only 8 cheat and 18 benign trials; the confidence intervals remain materially wider than the point estimates.
- Trials were collected on one host and software-version snapshot. Exact-hash allowlisting is intentionally version-specific.
- Several overlays required manual confirmation, creating variable stable and active windows.
- WebRadar frontend execution differed from calibration by explicit user request and is disclosed above.
- One valid cheat trial experienced concurrent monitoring overhead from a delayed duplicate launcher; both the deviation and sensitivity result are retained.
- The tested samples do not cover kernel-mode, DMA, injected, or novel access strategies beyond the stated experiment scope.

## Reproducibility artifacts

- `trial_results.csv`: per-trial decisions and latencies.
- `method_summary.csv`: final confusion matrices and Wilson intervals.
- `artifact_manifest.sha256.csv`: relative path, byte length, and SHA-256 for the report generator, report, frozen inputs, 26 source metadata files, 26 completed raw-data directories, and final analysis CSVs.
- Invalid duplicate-startup directories are preserved under `experiments/aborted_runs` but deliberately excluded from the held-out manifest and metrics.

No policy selection or trusted-list mutation is performed by this report generator.
