using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace CS2HandleMonitor;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (!MonitorOptions.TryParse(args, out MonitorOptions? options, out string? error))
        {
            if (error is not null) Console.Error.WriteLine(error);
            PrintUsage();
            return error is null ? 0 : 2;
        }

        MonitorOptions parsedOptions = options!;
        TargetIdentity[] initialTargets = DiscoverTargets(parsedOptions);
        if (initialTargets.Length == 0)
        {
            Console.Error.WriteLine($"未找到目标进程 {parsedOptions.ProcessName}.exe。");
            return 1;
        }

        string runId = $"handle_monitor_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
        string outputDirectory = Path.Combine(Path.GetFullPath(parsedOptions.OutputDirectory), runId);
        Directory.CreateDirectory(outputDirectory);
        string outputPath = Path.Combine(outputDirectory, "handles.csv");
        string summaryPath = Path.Combine(outputDirectory, "scan_summary.csv");
        string eventsPath = Path.Combine(outputDirectory, "handle_events.csv");
        string detectionsPath = Path.Combine(outputDirectory, "detections.csv");

        Console.WriteLine("CS2 Handle Monitor");
        Console.WriteLine(parsedOptions.ProcessId is null
            ? $"模式: 自动监控全部 {parsedOptions.ProcessName}.exe 实例"
            : $"模式: 仅监控 PID {parsedOptions.ProcessId}");
        foreach (TargetIdentity target in initialTargets) PrintTarget(target);
        Console.WriteLine($"间隔: {parsedOptions.IntervalSeconds} 秒");
        Console.WriteLine($"检测阈值: {parsedOptions.DetectionThreshold}");
        Console.WriteLine($"输出目录: {outputDirectory}");
        Console.WriteLine("提示：以管理员身份运行可提高句柄可见性。按 Ctrl+C 停止。");

        using CancellationTokenSource stopSource = new();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopSource.Cancel();
        };
        if (parsedOptions.DurationSeconds is int duration)
            stopSource.CancelAfter(TimeSpan.FromSeconds(duration));

        try
        {
            await MonitorAsync(parsedOptions, outputPath, summaryPath, eventsPath, detectionsPath, stopSource.Token);
        }
        catch (OperationCanceledException) { }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"监控失败：{exception.Message}");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine($"句柄记录：{outputPath}");
        Console.WriteLine($"扫描摘要：{summaryPath}");
        Console.WriteLine($"生命周期事件：{eventsPath}");
        Console.WriteLine($"检测告警：{detectionsPath}");
        return 0;
    }

    private static async Task MonitorAsync(
        MonitorOptions options,
        string outputPath,
        string summaryPath,
        string eventsPath,
        string detectionsPath,
        CancellationToken cancellationToken)
    {
        await using StreamWriter writer = CreateWriter(outputPath);
        await writer.WriteLineAsync(
            "TimestampUtc,ElapsedMs,TargetProcessId,TargetProcessName,TargetImagePath,TargetWindowTitle,TargetRole,SourceProcessId,SourceProcessName,SourceImagePath,ParentProcessId,SourceStartedUtc,SourceSha256,HasEmbeddedSignature,CertificateSubject,HandleValue,GrantedAccess,AccessRights,RawRiskScore,AdjustedRiskScore,Classification,RiskReasons,SystemHandleCount,SourceProcessesInspected,SourceProcessesDenied,DuplicateFailures");

        await using StreamWriter summaryWriter = CreateWriter(summaryPath);
        await summaryWriter.WriteLineAsync(
            "TimestampUtc,ElapsedMs,TargetProcessId,TargetProcessName,TargetImagePath,TargetWindowTitle,TargetRole,MatchedExternalHandles,HighRiskHandles,SystemHandleCount,SourceProcessesInspected,SourceProcessesDenied,DuplicateFailures");

        await using StreamWriter eventsWriter = CreateWriter(eventsPath);
        await eventsWriter.WriteLineAsync(
            "TimestampUtc,ElapsedMs,Event,DurationMs,TargetProcessId,TargetRole,SourceProcessId,SourceProcessName,SourceImagePath,ParentProcessId,SourceStartedUtc,SourceSha256,HasEmbeddedSignature,CertificateSubject,HandleValue,GrantedAccess,AccessRights,RawRiskScore,AdjustedRiskScore,Classification,RiskReasons");

        await using StreamWriter detectionsWriter = CreateWriter(detectionsPath);
        await detectionsWriter.WriteLineAsync(
            "TimestampUtc,ElapsedMs,TargetProcessId,TargetRole,SourceProcessId,SourceProcessName,SourceImagePath,ParentProcessId,SourceSha256,HasEmbeddedSignature,CertificateSubject,HandleValue,GrantedAccess,AccessRights,RawRiskScore,AdjustedRiskScore,Classification,RiskReasons");

        Stopwatch timer = Stopwatch.StartNew();
        Dictionary<HandleKey, ActiveHandle> activeHandles = [];
        using PeriodicTimer scanTimer = new(TimeSpan.FromSeconds(options.IntervalSeconds));
        do
        {
            TargetIdentity[] targets = DiscoverTargets(options);
            string timestamp = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);
            long elapsedMs = timer.ElapsedMilliseconds;
            int totalMatches = 0;
            int totalHighRisk = 0;
            int maximumDenied = 0;
            HashSet<HandleKey> currentHandles = [];

            foreach (TargetIdentity target in targets)
            {
                HandleScanResult result = SystemHandleScanner.FindHandlesToProcess(target.ProcessId);
                int highRisk = result.Handles.Count(handle =>
                    DetectionEngine.Evaluate(target, handle, options.DetectionThreshold).IsDetection);
                totalMatches += result.Handles.Count;
                totalHighRisk += highRisk;
                maximumDenied = Math.Max(maximumDenied, result.SourceProcessesDenied);

                foreach (TargetHandle handle in result.Handles)
                {
                    DetectionDecision decision = DetectionEngine.Evaluate(target, handle, options.DetectionThreshold);
                    HandleKey key = new(target.ProcessId, handle.SourceProcessId, handle.HandleValue, handle.GrantedAccess);
                    currentHandles.Add(key);
                    await writer.WriteLineAsync(string.Join(',',
                        timestamp,
                        elapsedMs.ToString(CultureInfo.InvariantCulture),
                        target.ProcessId.ToString(CultureInfo.InvariantCulture),
                        EscapeCsv(target.ProcessName),
                        EscapeCsv(target.ImagePath),
                        EscapeCsv(target.WindowTitle),
                        target.Role,
                        handle.SourceProcessId.ToString(CultureInfo.InvariantCulture),
                        EscapeCsv(handle.SourceProcessName),
                        EscapeCsv(handle.SourceImagePath),
                        handle.ParentProcessId.ToString(CultureInfo.InvariantCulture),
                        handle.SourceStartedUtc,
                        handle.SourceSha256,
                        handle.HasEmbeddedSignature ? "true" : "false",
                        EscapeCsv(handle.CertificateSubject),
                        $"0x{handle.HandleValue:X}",
                        $"0x{handle.GrantedAccess:X8}",
                        EscapeCsv(handle.AccessRights),
                        decision.RawRiskScore.ToString(CultureInfo.InvariantCulture),
                        decision.AdjustedRiskScore.ToString(CultureInfo.InvariantCulture),
                        decision.Classification,
                        EscapeCsv(decision.RiskReasons),
                        result.SystemHandleCount.ToString(CultureInfo.InvariantCulture),
                        result.SourceProcessesInspected.ToString(CultureInfo.InvariantCulture),
                        result.SourceProcessesDenied.ToString(CultureInfo.InvariantCulture),
                        result.DuplicateFailures.ToString(CultureInfo.InvariantCulture)));

                    if (!activeHandles.ContainsKey(key))
                    {
                        ActiveHandle opened = new(target, handle, decision, DateTime.UtcNow, elapsedMs);
                        activeHandles.Add(key, opened);
                        await WriteHandleEventAsync(eventsWriter, "Opened", opened, DateTime.UtcNow, elapsedMs);
                        if (decision.IsDetection)
                        {
                            await WriteDetectionAsync(detectionsWriter, target, handle, decision, DateTime.UtcNow, elapsedMs);
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[DETECTED] {handle.SourceProcessName}.exe PID={handle.SourceProcessId} -> {target.ProcessName}.exe PID={target.ProcessId}  Risk={decision.AdjustedRiskScore}");
                            Console.ResetColor();
                        }
                    }
                }

                await summaryWriter.WriteLineAsync(string.Join(',',
                    timestamp,
                    elapsedMs.ToString(CultureInfo.InvariantCulture),
                    target.ProcessId.ToString(CultureInfo.InvariantCulture),
                    EscapeCsv(target.ProcessName),
                    EscapeCsv(target.ImagePath),
                    EscapeCsv(target.WindowTitle),
                    target.Role,
                    result.Handles.Count.ToString(CultureInfo.InvariantCulture),
                    highRisk.ToString(CultureInfo.InvariantCulture),
                    result.SystemHandleCount.ToString(CultureInfo.InvariantCulture),
                    result.SourceProcessesInspected.ToString(CultureInfo.InvariantCulture),
                    result.SourceProcessesDenied.ToString(CultureInfo.InvariantCulture),
                    result.DuplicateFailures.ToString(CultureInfo.InvariantCulture)));
            }

            foreach (HandleKey closedKey in activeHandles.Keys.Where(key => !currentHandles.Contains(key)).ToArray())
            {
                ActiveHandle closed = activeHandles[closedKey];
                await WriteHandleEventAsync(eventsWriter, "Closed", closed, DateTime.UtcNow, elapsedMs);
                activeHandles.Remove(closedKey);
            }

            await writer.FlushAsync(cancellationToken);
            await summaryWriter.FlushAsync(cancellationToken);
            await eventsWriter.FlushAsync(cancellationToken);
            await detectionsWriter.FlushAsync(cancellationToken);
            Console.Write($"\r{timer.Elapsed:mm\\:ss}  目标: {targets.Length}  外部句柄: {totalMatches}  高风险: {totalHighRisk}  无权检查进程: {maximumDenied}   ");
        }
        while (await scanTimer.WaitForNextTickAsync(cancellationToken));
    }

    private static async Task WriteDetectionAsync(
        StreamWriter writer,
        TargetIdentity target,
        TargetHandle handle,
        DetectionDecision decision,
        DateTime observedUtc,
        long elapsedMs)
    {
        await writer.WriteLineAsync(string.Join(',',
            observedUtc.ToString("O", CultureInfo.InvariantCulture),
            elapsedMs.ToString(CultureInfo.InvariantCulture),
            target.ProcessId.ToString(CultureInfo.InvariantCulture),
            target.Role,
            handle.SourceProcessId.ToString(CultureInfo.InvariantCulture),
            EscapeCsv(handle.SourceProcessName),
            EscapeCsv(handle.SourceImagePath),
            handle.ParentProcessId.ToString(CultureInfo.InvariantCulture),
            handle.SourceSha256,
            handle.HasEmbeddedSignature ? "true" : "false",
            EscapeCsv(handle.CertificateSubject),
            $"0x{handle.HandleValue:X}",
            $"0x{handle.GrantedAccess:X8}",
            EscapeCsv(handle.AccessRights),
            decision.RawRiskScore.ToString(CultureInfo.InvariantCulture),
            decision.AdjustedRiskScore.ToString(CultureInfo.InvariantCulture),
            decision.Classification,
            EscapeCsv(decision.RiskReasons)));
    }

    private static async Task WriteHandleEventAsync(
        StreamWriter writer,
        string eventName,
        ActiveHandle active,
        DateTime observedUtc,
        long elapsedMs)
    {
        TargetHandle handle = active.Handle;
        DetectionDecision decision = active.Decision;
        await writer.WriteLineAsync(string.Join(',',
            observedUtc.ToString("O", CultureInfo.InvariantCulture),
            elapsedMs.ToString(CultureInfo.InvariantCulture),
            eventName,
            Math.Max(0, elapsedMs - active.FirstSeenElapsedMs).ToString(CultureInfo.InvariantCulture),
            active.Target.ProcessId.ToString(CultureInfo.InvariantCulture),
            active.Target.Role,
            handle.SourceProcessId.ToString(CultureInfo.InvariantCulture),
            EscapeCsv(handle.SourceProcessName),
            EscapeCsv(handle.SourceImagePath),
            handle.ParentProcessId.ToString(CultureInfo.InvariantCulture),
            handle.SourceStartedUtc,
            handle.SourceSha256,
            handle.HasEmbeddedSignature ? "true" : "false",
            EscapeCsv(handle.CertificateSubject),
            $"0x{handle.HandleValue:X}",
            $"0x{handle.GrantedAccess:X8}",
            EscapeCsv(handle.AccessRights),
            decision.RawRiskScore.ToString(CultureInfo.InvariantCulture),
            decision.AdjustedRiskScore.ToString(CultureInfo.InvariantCulture),
            decision.Classification,
            EscapeCsv(decision.RiskReasons)));
    }

    private static TargetIdentity[] DiscoverTargets(MonitorOptions options)
    {
        IEnumerable<Process> candidates;
        try
        {
            candidates = options.ProcessId is int id
                ? [Process.GetProcessById(id)]
                : Process.GetProcessesByName(options.ProcessName);
        }
        catch
        {
            return [];
        }

        List<TargetIdentity> targets = [];
        foreach (Process process in candidates)
        {
            using (process)
            {
                if (!string.Equals(SafeRead(() => process.ProcessName, string.Empty), options.ProcessName,
                        StringComparison.OrdinalIgnoreCase) || SafeRead(() => process.HasExited, true))
                    continue;

                string name = SafeRead(() => process.ProcessName, options.ProcessName);
                string imagePath = SafeRead(() => process.MainModule?.FileName ?? string.Empty, string.Empty);
                string windowTitle = SafeRead(() => process.MainWindowTitle, string.Empty);
                string role = InferRole(windowTitle, imagePath);
                targets.Add(new TargetIdentity(process.Id, name, imagePath, windowTitle, role));
            }
        }

        return targets.OrderBy(target => target.Role).ThenBy(target => target.ProcessId).ToArray();
    }

    private static string InferRole(string windowTitle, string imagePath)
    {
        if (imagePath.Contains("\\steamcmd\\", StringComparison.OrdinalIgnoreCase))
            return "DedicatedServer";
        if (windowTitle.Contains("Counter-Strike 2", StringComparison.OrdinalIgnoreCase)) return "Client";
        return string.IsNullOrWhiteSpace(windowTitle) ? "HeadlessOrServer" : "ServerOrOther";
    }

    private static void PrintTarget(TargetIdentity target) =>
        Console.WriteLine($"目标: PID {target.ProcessId}, 角色 {target.Role}, 窗口 {target.WindowTitle}");

    private static StreamWriter CreateWriter(string path) => new(
        new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read),
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

    private static T SafeRead<T>(Func<T> action, T fallback)
    {
        try { return action(); }
        catch { return fallback; }
    }

    private static string EscapeCsv(string value) =>
        value.IndexOfAny([',', '"', '\r', '\n']) < 0 ? value : $"\"{value.Replace("\"", "\"\"")}\"";

    private static void PrintUsage()
    {
        Console.WriteLine("用法: dotnet run --project CS2HandleMonitor -- [参数]");
        Console.WriteLine("  --pid <PID>                 只监控指定 PID；省略时监控全部同名进程");
        Console.WriteLine("  --process <名称>            目标进程名称，默认 cs2");
        Console.WriteLine("  --interval-seconds <秒>     扫描间隔，默认 2");
        Console.WriteLine("  --duration-seconds <秒>     自动停止时长，可选");
        Console.WriteLine("  --threshold <0-100>         实时检测阈值，默认 60");
        Console.WriteLine("  --output <目录>             输出根目录，默认 ./data");
        Console.WriteLine("  --help                      显示帮助");
    }
}

internal sealed record TargetIdentity(
    int ProcessId,
    string ProcessName,
    string ImagePath,
    string WindowTitle,
    string Role);

internal readonly record struct HandleKey(
    int TargetProcessId,
    int SourceProcessId,
    ulong HandleValue,
    uint GrantedAccess);

internal sealed record ActiveHandle(
    TargetIdentity Target,
    TargetHandle Handle,
    DetectionDecision Decision,
    DateTime FirstSeenUtc,
    long FirstSeenElapsedMs);

internal sealed record MonitorOptions(
    int? ProcessId,
    string ProcessName,
    int IntervalSeconds,
    int? DurationSeconds,
    int DetectionThreshold,
    string OutputDirectory)
{
    internal static bool TryParse(string[] args, out MonitorOptions? options, out string? error)
    {
        options = null;
        error = null;
        if (args.Any(arg => arg is "--help" or "-h")) return false;

        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
        for (int index = 0; index < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
            {
                error = $"参数格式错误：{args[index]}";
                return false;
            }
            values[args[index]] = args[index + 1];
        }

        HashSet<string> known = new(StringComparer.OrdinalIgnoreCase)
            { "--pid", "--process", "--interval-seconds", "--duration-seconds", "--threshold", "--output" };
        string? unknown = values.Keys.FirstOrDefault(key => !known.Contains(key));
        if (unknown is not null) { error = $"未知参数：{unknown}"; return false; }

        if (!OptionalPositive(values, "--pid", out int? pid, out error) ||
            !Positive(values, "--interval-seconds", 2, out int interval, out error) ||
            !OptionalPositive(values, "--duration-seconds", out int? duration, out error) ||
            !Range(values, "--threshold", 60, 0, 100, out int threshold, out error)) return false;

        options = new MonitorOptions(
            pid,
            values.GetValueOrDefault("--process", "cs2"),
            interval,
            duration,
            threshold,
            values.GetValueOrDefault("--output", "data"));
        return true;
    }

    private static bool Positive(Dictionary<string, string> values, string key, int fallback, out int value, out string? error)
    {
        error = null;
        if (!values.TryGetValue(key, out string? text)) { value = fallback; return true; }
        if (int.TryParse(text, out value) && value > 0) return true;
        error = $"{key} 必须是正整数。";
        return false;
    }

    private static bool OptionalPositive(Dictionary<string, string> values, string key, out int? value, out string? error)
    {
        value = null;
        error = null;
        if (!values.TryGetValue(key, out string? text)) return true;
        if (int.TryParse(text, out int parsed) && parsed > 0) { value = parsed; return true; }
        error = $"{key} 必须是正整数。";
        return false;
    }

    private static bool Range(Dictionary<string, string> values, string key, int fallback, int minimum, int maximum, out int value, out string? error)
    {
        error = null;
        if (!values.TryGetValue(key, out string? text)) { value = fallback; return true; }
        if (int.TryParse(text, out value) && value >= minimum && value <= maximum) return true;
        error = $"{key} 必须在 {minimum} 到 {maximum} 之间。";
        return false;
    }
}
