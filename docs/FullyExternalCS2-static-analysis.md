# FullyExternalCS2 Static Behavior Analysis

Analysis target: `D:\Software\FullyExternalCS2-main`

Method: Static source-code inspection only; the target program was not run.

Analysis date: 2026-08-04

## Executive Summary

This project is an external CS2 assistance program. It does not inject a DLL into CS2, and the current source code does not write to CS2 memory. It uses `System.Diagnostics.Process` to find `cs2.exe`, obtains a process handle, and calls `ReadProcessMemory` at high frequency to read player, entity, bone, view-angle, weapon, bomb, and vote data. It displays ESP through a separate transparent overlay and uses `SendInput` to generate mouse movement and clicks for Aimbot, RCS, and TriggerBot.

Therefore, the strongest host-side detection signals are not changes to CS2 modules, but instead:

1. an untrusted process holding a VM-readable handle to `cs2.exe`;
2. sustained, high-frequency reads of CS2 virtual memory by that process;
3. the same process creating a transparent tool window over CS2;
4. the same process calling `SendInput` to generate mouse movement or clicks;
5. access to `raw.githubusercontent.com/a2x/cs2-dumper/...` at startup to retrieve offsets.

## Key Evidence

### Process Discovery and Module Location

- `Data/Game/GameProcess.cs:82` uses `Process.GetProcessesByName("cs2")` to find the game.
- `Data/Game/GameProcess.cs:87` enumerates `Process.Modules` and locates `client.dll`.
- `Utils/Utility.cs:317` and `:324` read `Process.Handle`, which causes .NET to obtain a native handle to the target process.
- The source code does not directly declare `OpenProcess`; a source-string search alone therefore cannot establish that the application itself invokes `OpenProcess` through P/Invoke. The subsequent `ReadProcessMemory` calls must nevertheless use a process handle with permission to read CS2.

### External Memory Reads

- `Core/Kernel32.cs:8` directly declares `kernel32!ReadProcessMemory`.
- `Utils/Utility.cs:328-343` reads arbitrary unmanaged types.
- `Utils/Utility.cs:348-365` reads strings up to 256 bytes long.
- `Data/Game/GameData.cs` uses the 1 ms loop from `ThreadedServiceBase` by default to update the local player and 64 entities in sequence.
- `Data/Entity/EntityBase.cs` reads life state, health, team, position, shot count, weapon, and velocity during each update.
- `Data/Entity/Entity.cs` reads the entity controller, Pawn, visibility/aim/flash state, name, and 17 bone positions.
- `Data/Entity/Player.cs` reads the view matrix, view angles, recoil, and player flags.
- `Features/BombTimer.cs`, `VoteTeller.cs`, and `TriggerBot.cs` also read game state from their own threads.

This creates a conspicuous and sustained pattern of cross-process VM reads. The exact read count depends on the number of valid entities and actual thread scheduling, so a fixed reads-per-second figure cannot be derived reliably from static code alone.

### Synthetic Input

- `Core/User32.cs:45` declares `user32!SendInput`.
- `Utils/Utility.cs:120-138` generates relative mouse movement.
- `Utils/Utility.cs:189-225` generates left-mouse-button presses and releases.
- `Features/AimBot.cs:194` invokes mouse movement to implement Aimbot/RCS.
- `Features/TriggerBot.cs:97-100` sends a left-click after a delay.
- The current `config.json` enables AimBot, RCS, and TriggerBot by default.

### Overlay and Window Behavior

- The project depends on `ClickableTransparentOverlay 11.1.0` and ImGui.
- `Graphics/OverlayRenderer.cs` creates a separate overlay and configures it with `WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW`.
- The overlay follows the position and size of the CS2 client area and renders ESP, bones, a crosshair, a bomb timer, and menus.
- This is an external window overlay rather than a module injected into CS2, so inspecting only CS2's own module list will not reveal the program.

### Network Behavior

- `Utils/Offsets.cs:78-81` accesses `cs2-dumper` on GitHub Raw at startup:
  - `output/offsets.json`
  - `output/client_dll.json`
- The downloaded data updates CS2 addresses and field offsets.

### Behaviors Not Found

The current C# source code contains no evidence of:

- `WriteProcessMemory`;
- `VirtualAllocEx` / `VirtualProtectEx`;
- `CreateRemoteThread`;
- DLL injection or manual mapping;
- kernel-driver interaction;
- modification of CS2 process memory.

`GlobalHook.cs` contains a `SetWindowsHookEx` wrapper, but the current project contains no code that instantiates or calls it. It should be treated as unused code, not as behavior observed at runtime.

## Recommendations for the Monitoring Tool

### High-Value Events

1. Enumerate system handles, identify every external process handle targeting `cs2.exe`, and record the source PID, image path, signature, `GrantedAccess`, and first/last observation time.
2. Treat handles containing `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION` as strong signals, while maintaining allowlists for Steam, GPU drivers, recording software, and accessibility software.
3. Record whether a suspicious source process owns a transparent or tool window that covers the CS2 client area.
4. Record `SendInput` activity from suspicious source processes. If reliable attribution is not possible in user mode, validate it experimentally with ETW, API tracing, or controlled instrumentation.
5. Record network connections to the GitHub Raw `a2x/cs2-dumper` path as a supporting signal, not as a standalone basis for blocking.

### Initial Risk-Scoring Draft

| Signal | Suggested score |
|---|---:|
| Non-allowlisted process holds a CS2 `VM_READ` handle | +40 |
| Sustained high-frequency cross-process memory reads | +30 |
| Same process creates a transparent tool window over CS2 | +15 |
| Same process generates mouse input | +20 |
| Retrieves public CS2 offset data | +10 |
| Unknown injected module found inside CS2 | +50 |

An initial alert threshold of 60 is recommended. This score should be used only for experiments and alert prioritization. Before it is used for enforcement, the false-positive rate must be calibrated against control data from legitimate software.

## Limitations

- These conclusions are based on static source code and cannot prove that locally compiled binaries exactly match that source.
- The program was not run, so handle permissions, API-call frequency, window properties, and network traffic were not measured.
- The exact access mask requested when .NET obtains `Process.Handle` should be recorded during dynamic experiments rather than inferred from static code.
