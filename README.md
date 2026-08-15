# CS2 Anti-cheating Research

当前阶段用于建立可重复的 CS2 正常/测试行为基线。`CS2BaselineLogger` 只进行进程观测，不修改目标进程。

## 构建

```powershell
dotnet build Anti_cheating.sln
```

## 采集一次实验

```powershell
dotnet run --project CS2BaselineLogger -- `
  --experiment baseline_dust2_01 `
  --cheat false `
  --map de_dust2 `
  --mode competitive `
  --bots 9 `
  --duration-seconds 600
```

如果存在多个 `cs2.exe`，程序会要求选择 PID，也可以通过 `--pid 1234` 直接指定。运行 `--help` 查看全部参数。

每次运行会创建唯一目录，包含：

- `metadata.json`：实验条件和主机信息；
- `metrics.csv`：CPU、内存、线程、句柄数、模块数等时间序列；
- `modules.csv`：定期采集的模块名称、路径、基址、大小和版本。

## 实验规范

开始一组对照实验前，应固定：

1. CS2、服务器和测试程序版本；
2. 地图、模式、Bot 数量与难度；
3. 分辨率、画质、FPS 上限和后台程序；
4. 每次实验的预热时间与采集时长；
5. 每类实验至少重复多次，并为标签保留独立记录。

FPS 尚未纳入当前采集器。模块加载和句柄数量也只能作为风险信号，不能单独证明作弊。

## 外部句柄监控

`CS2HandleMonitor` 枚举指向 CS2 的外部进程句柄，记录源进程、映像路径、`GrantedAccess`、权限解释和初始风险分值。建议在管理员 PowerShell 中运行以提高句柄可见性：

```powershell
dotnet run --project CS2HandleMonitor -- `
  --process cs2 `
  --interval-seconds 2 `
  --duration-seconds 600
```

省略 `--pid` 时，监控器会在每次扫描中自动发现并监控全部 `cs2.exe`，并根据窗口标题将目标标记为 `Client`、`HeadlessOrServer` 或 `ServerOrOther`。如需固定单个实验目标，可显式传入 `--pid`。

输出位于唯一的 `data/handle_monitor_*` 目录中：`handles.csv` 保存匹配的外部句柄快照，`scan_summary.csv` 保存每次扫描的完整性统计，`handle_events.csv` 保存 `Opened`/`Closed` 生命周期事件和持续时间，`detections.csv` 保存超过检测阈值的新告警。通过 `--threshold 60` 可调整实时检测阈值。源进程身份包含父 PID、启动时间、SHA-256 和嵌入签名证书主题。`HasEmbeddedSignature` 只表示文件包含证书，不代表证书链已经验证可信。目标进程自身的句柄会被排除。该工具只读取和复制句柄用于识别，不会关闭外部句柄或修改目标进程。`VM_READ` 也可能由合法 Overlay、录屏、驱动工具或辅助功能软件使用，必须结合签名、路径、持续时间和其他行为判断。
