# FullyExternalCS2 静态行为分析

分析对象：`D:\Software\FullyExternalCS2-main`  
分析方式：仅源代码静态检查，未运行目标程序。  
分析日期：2026-08-04

## 结论摘要

该项目是一个外部 CS2 辅助程序。它不把 DLL 注入 CS2，也没有在当前源码中写入 CS2 内存；它通过 `System.Diagnostics.Process` 找到 `cs2.exe`，取得进程句柄并高频调用 `ReadProcessMemory`，读取玩家、实体、骨骼、视角、武器、炸弹和投票数据。它通过独立透明 Overlay 显示 ESP，并通过 `SendInput` 生成鼠标移动和点击，实现 Aimbot、RCS 和 TriggerBot。

因此，最强的主机侧检测信号不是 CS2 模块变化，而是：

1. 非受信任进程持有指向 `cs2.exe` 的可读 VM 句柄；
2. 该进程持续、高频读取 CS2 虚拟内存；
3. 同一进程创建覆盖 CS2 的透明工具窗口；
4. 同一进程调用 `SendInput` 生成鼠标移动或点击；
5. 启动时访问 `raw.githubusercontent.com/a2x/cs2-dumper/...` 获取偏移。

## 关键证据

### 进程发现与模块定位

- `Data/Game/GameProcess.cs:82` 使用 `Process.GetProcessesByName("cs2")` 查找游戏。
- `Data/Game/GameProcess.cs:87` 枚举 `Process.Modules` 并定位 `client.dll`。
- `Utils/Utility.cs:317` 和 `:324` 读取 `Process.Handle`，该属性会让 .NET 获取目标进程的原生句柄。
- 源码没有直接声明 `OpenProcess`；因此不能仅靠源代码字符串搜索断言应用程序自己 P/Invoke 了 `OpenProcess`。但后续 `ReadProcessMemory` 必须使用一个对 CS2 有读取权限的进程句柄。

### 外部内存读取

- `Core/Kernel32.cs:8` 直接声明 `kernel32!ReadProcessMemory`。
- `Utils/Utility.cs:328-343` 对任意非托管类型执行读取。
- `Utils/Utility.cs:348-365` 读取最长 256 字节的字符串。
- `Data/Game/GameData.cs` 默认使用 `ThreadedServiceBase` 的 1 ms 循环，依次更新本地玩家和 64 个实体。
- `Data/Entity/EntityBase.cs` 每次更新读取生命状态、生命值、队伍、位置、射击数、武器和速度。
- `Data/Entity/Entity.cs` 读取实体控制器、Pawn、可见/瞄准/闪光状态、名字以及 17 个骨骼位置。
- `Data/Entity/Player.cs` 读取视图矩阵、视角、后坐力和玩家标志。
- `Features/BombTimer.cs`、`VoteTeller.cs` 和 `TriggerBot.cs` 还会在各自线程中读取游戏状态。

这会形成明显的、持续的跨进程 VM-read 行为。精确读取次数取决于有效实体数量和线程实际调度，不能仅凭静态代码可靠换算为固定 reads/s。

### 合成输入

- `Core/User32.cs:45` 声明 `user32!SendInput`。
- `Utils/Utility.cs:120-138` 生成相对鼠标移动。
- `Utils/Utility.cs:189-225` 生成鼠标左键按下和释放。
- `Features/AimBot.cs:194` 调用鼠标移动实现 Aimbot/RCS。
- `Features/TriggerBot.cs:97-100` 延迟后发送左键点击。
- 当前 `config.json` 默认启用 AimBot、RCS 和 TriggerBot。

### Overlay 与窗口行为

- 项目依赖 `ClickableTransparentOverlay 11.1.0` 和 ImGui。
- `Graphics/OverlayRenderer.cs` 创建独立 Overlay，并将其设置为 `WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW`。
- Overlay 跟随 CS2 客户区位置与大小，绘制 ESP、骨骼、准星、炸弹计时和菜单。
- 这是外部窗口覆盖，不是向 CS2 注入模块，因此仅检查 CS2 自身模块列表不会发现该程序。

### 网络行为

- `Utils/Offsets.cs:78-81` 启动时访问 GitHub Raw 上的 `cs2-dumper`：
  - `output/offsets.json`
  - `output/client_dll.json`
- 下载结果用于更新 CS2 地址和字段偏移。

### 未发现的行为

在当前 C# 源码中未发现：

- `WriteProcessMemory`；
- `VirtualAllocEx` / `VirtualProtectEx`；
- `CreateRemoteThread`；
- DLL 注入或手工映射；
- 内核驱动交互；
- 修改 CS2 进程内存。

`GlobalHook.cs` 包含 `SetWindowsHookEx` 封装，但当前项目中没有发现实例化或调用它的代码，应视为未使用代码，而不是已发生的运行时行为。

## 对 Monitoring Tool 的建议

### 高价值事件

1. 枚举系统句柄，找出所有以 `cs2.exe` 为目标的外部进程句柄，并记录：源 PID、映像路径、签名、GrantedAccess、首次/最后观察时间。
2. 将含 `PROCESS_VM_READ` 和 `PROCESS_QUERY_INFORMATION` 的句柄作为强信号，但维护 Steam、GPU 驱动、录屏和辅助功能软件白名单。
3. 记录可疑源进程是否存在覆盖 CS2 客户区的透明/工具窗口。
4. 记录可疑源进程的 `SendInput` 行为；若无法在用户态可靠归因，应在实验中使用 ETW、API tracing 或受控插桩验证。
5. 记录到 GitHub Raw `a2x/cs2-dumper` 路径的网络连接，作为辅助信号而非单独封禁依据。

### 初始风险评分草案

| 信号 | 建议分值 |
|---|---:|
| 非白名单进程持有 CS2 `VM_READ` 句柄 | +40 |
| 持续高频跨进程内存读取 | +30 |
| 同进程创建覆盖 CS2 的透明工具窗口 | +15 |
| 同进程生成鼠标输入 | +20 |
| 获取公开 CS2 offsets 数据 | +10 |
| 在 CS2 内发现未知注入模块 | +50 |

建议初始告警阈值为 60 分。该评分只能用于实验和告警排序，必须通过正常软件对照数据校准误报率后才能用于处置。

## 限制

- 这是源代码静态结论，不能证明本地已编译二进制与源码完全一致。
- 未运行程序，因此没有实测句柄权限、API 调用频率、窗口属性或网络流量。
- .NET 获取 `Process.Handle` 时的具体访问掩码应在动态实验中记录，而不要依据静态代码猜测。
