using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (!LoggerOptions.TryParse(args, out LoggerOptions? options, out string? error))
        {
            if (!string.IsNullOrWhiteSpace(error))
            {
                Console.Error.WriteLine(error);
                Console.Error.WriteLine();
            }

            PrintUsage();
            return error is null ? 0 : 2;
        }

        string runId = $"{MakeSafeFileName(options!.Experiment)}_{DateTime.UtcNow:yyyyMMdd_HHmmss}";
        string runDirectory = Path.Combine(Path.GetFullPath(options.OutputDirectory), runId);
        Directory.CreateDirectory(runDirectory);

        string metricsPath = Path.Combine(runDirectory, "metrics.csv");
        string modulesPath = Path.Combine(runDirectory, "modules.csv");
        string metadataPath = Path.Combine(runDirectory, "metadata.json");

        Process? process = await SelectProcessAsync(options);
        if (process is null)
        {
            Console.Error.WriteLine($"未找到目标进程 {options.ProcessName}.exe。");
            return 1;
        }

        ExperimentMetadata metadata = new(
            runId,
            options.Experiment,
            options.CheatEnabled,
            options.Map,
            options.Mode,
            options.BotCount,
            options.Notes,
            process.Id,
            process.ProcessName,
            DateTime.UtcNow,
            options.SampleIntervalMs,
            options.ModuleSnapshotSeconds,
            options.DurationSeconds,
            Environment.MachineName,
            Environment.OSVersion.ToString(),
            Environment.ProcessorCount);

        await File.WriteAllTextAsync(
            metadataPath,
            JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        Console.WriteLine("CS2 Baseline Logger");
        Console.WriteLine($"Run ID: {runId}");
        Console.WriteLine($"目标: {process.ProcessName}.exe (PID {process.Id})");
        Console.WriteLine($"采样间隔: {options.SampleIntervalMs} ms");
        Console.WriteLine($"输出目录: {runDirectory}");
        Console.WriteLine("按 Ctrl+C 停止记录。");

        using CancellationTokenSource stopSource = new();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopSource.Cancel();
        };

        if (options.DurationSeconds is int durationSeconds)
        {
            stopSource.CancelAfter(TimeSpan.FromSeconds(durationSeconds));
        }

        try
        {
            await RecordAsync(process, options, metricsPath, modulesPath, stopSource.Token);
        }
        catch (OperationCanceledException)
        {
            // 用户停止或到达指定实验时长。
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"记录失败：{exception.Message}");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine("记录已结束。");
        Console.WriteLine($"指标: {metricsPath}");
        Console.WriteLine($"模块: {modulesPath}");
        Console.WriteLine($"元数据: {metadataPath}");
        return 0;
    }

    private static async Task RecordAsync(
        Process process,
        LoggerOptions options,
        string metricsPath,
        string modulesPath,
        CancellationToken cancellationToken)
    {
        await using StreamWriter metricsWriter = CreateWriter(metricsPath);
        await using StreamWriter modulesWriter = CreateWriter(modulesPath);

        await metricsWriter.WriteLineAsync(
            "TimestampUtc,ElapsedMs,ActualIntervalMs,ProcessId,CpuPercent,WorkingSetMB,PrivateMemoryMB,ThreadCount,HandleCount,ModuleCount,Responding");
        await modulesWriter.WriteLineAsync(
            "TimestampUtc,ElapsedMs,ProcessId,ModuleName,FilePath,BaseAddress,ModuleMemoryMB,FileVersion");

        Stopwatch experimentTimer = Stopwatch.StartNew();
        Stopwatch cpuTimer = Stopwatch.StartNew();
        TimeSpan previousCpuTime = process.TotalProcessorTime;
        long previousSampleElapsedMs = 0;
        long sampleNumber = 0;
        int latestModuleCount = -1;

        using CancellationTokenSource moduleSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task moduleTask = RecordModuleSnapshotsAsync(
            process,
            modulesWriter,
            experimentTimer,
            options.ModuleSnapshotSeconds,
            count => Interlocked.Exchange(ref latestModuleCount, count),
            moduleSource.Token);

        using PeriodicTimer sampleTimer = new(TimeSpan.FromMilliseconds(options.SampleIntervalMs));

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (SafeRead(() => process.HasExited, true))
                {
                    Console.WriteLine("目标进程已退出，停止记录。");
                    break;
                }

                process.Refresh();
                TimeSpan currentCpuTime = process.TotalProcessorTime;
                double cpuPercent = CalculateCpuPercent(previousCpuTime, currentCpuTime, cpuTimer.Elapsed.TotalSeconds);
                previousCpuTime = currentCpuTime;
                cpuTimer.Restart();

                long elapsedMs = experimentTimer.ElapsedMilliseconds;
                long actualIntervalMs = sampleNumber == 0 ? 0 : elapsedMs - previousSampleElapsedMs;
                previousSampleElapsedMs = elapsedMs;
                string line = string.Join(",",
                    DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    elapsedMs.ToString(CultureInfo.InvariantCulture),
                    actualIntervalMs.ToString(CultureInfo.InvariantCulture),
                    process.Id.ToString(CultureInfo.InvariantCulture),
                    cpuPercent.ToString("F4", CultureInfo.InvariantCulture),
                    (process.WorkingSet64 / 1024.0 / 1024.0).ToString("F4", CultureInfo.InvariantCulture),
                    (process.PrivateMemorySize64 / 1024.0 / 1024.0).ToString("F4", CultureInfo.InvariantCulture),
                    SafeRead(() => process.Threads.Count, -1).ToString(CultureInfo.InvariantCulture),
                    SafeRead(() => process.HandleCount, -1).ToString(CultureInfo.InvariantCulture),
                    Volatile.Read(ref latestModuleCount).ToString(CultureInfo.InvariantCulture),
                    SafeRead(() => process.Responding, false) ? "true" : "false");

                await metricsWriter.WriteLineAsync(line);

                sampleNumber++;
                if (sampleNumber % Math.Max(1, 1000 / options.SampleIntervalMs) == 0)
                {
                    await metricsWriter.FlushAsync(cancellationToken);
                    Console.Write($"\r时间: {experimentTimer.Elapsed:mm\\:ss}  CPU: {cpuPercent:F1}%  内存: {process.WorkingSet64 / 1024.0 / 1024.0:F0} MB   ");
                }

                if (!await sampleTimer.WaitForNextTickAsync(cancellationToken))
                {
                    break;
                }
            }
        }
        finally
        {
            moduleSource.Cancel();
            try { await moduleTask; }
            catch (OperationCanceledException) { }
        }

        await metricsWriter.FlushAsync(CancellationToken.None);
        await modulesWriter.FlushAsync(CancellationToken.None);
    }

    private static async Task RecordModuleSnapshotsAsync(
        Process process,
        StreamWriter writer,
        Stopwatch experimentTimer,
        int snapshotSeconds,
        Action<int> updateModuleCount,
        CancellationToken cancellationToken)
    {
        using PeriodicTimer snapshotTimer = new(TimeSpan.FromSeconds(snapshotSeconds));
        while (!cancellationToken.IsCancellationRequested)
        {
            int count = await WriteModuleSnapshotAsync(process, writer, experimentTimer.ElapsedMilliseconds);
            if (count >= 0)
            {
                updateModuleCount(count);
                await writer.FlushAsync(cancellationToken);
            }

            if (!await snapshotTimer.WaitForNextTickAsync(cancellationToken))
            {
                break;
            }
        }
    }

    private static async Task<int> WriteModuleSnapshotAsync(Process process, StreamWriter writer, long elapsedMs)
    {
        ProcessModule[] modules;
        try
        {
            modules = process.Modules.Cast<ProcessModule>().ToArray();
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"\n模块快照失败：{exception.Message}");
            return -1;
        }

        string timestamp = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        foreach (ProcessModule module in modules)
        {
            string row = string.Join(",",
                timestamp,
                elapsedMs.ToString(CultureInfo.InvariantCulture),
                process.Id.ToString(CultureInfo.InvariantCulture),
                EscapeCsv(SafeRead(() => module.ModuleName, string.Empty)),
                EscapeCsv(SafeRead(() => module.FileName, string.Empty)),
                $"0x{SafeRead(() => module.BaseAddress.ToInt64(), 0L):X}",
                (SafeRead(() => module.ModuleMemorySize, 0) / 1024.0 / 1024.0).ToString("F4", CultureInfo.InvariantCulture),
                EscapeCsv(SafeRead(() => module.FileVersionInfo.FileVersion ?? string.Empty, string.Empty)));
            await writer.WriteLineAsync(row);
        }

        return modules.Length;
    }

    private static StreamWriter CreateWriter(string path) => new(
        new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read),
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

    private static async Task<Process?> SelectProcessAsync(LoggerOptions options)
    {
        if (options.ProcessId is int processId)
        {
            try
            {
                Process selected = Process.GetProcessById(processId);
                if (!string.Equals(selected.ProcessName, options.ProcessName, StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine($"PID {processId} 是 {selected.ProcessName}.exe，不是 {options.ProcessName}.exe。");
                    return null;
                }

                return selected;
            }
            catch
            {
                return null;
            }
        }

        Console.WriteLine($"正在等待 {options.ProcessName}.exe……");
        while (true)
        {
            Process[] processes = Process.GetProcessesByName(options.ProcessName);
            if (processes.Length == 1)
            {
                return processes[0];
            }

            if (processes.Length > 1)
            {
                foreach (Process candidate in processes.OrderBy(process => process.Id))
                {
                    Console.WriteLine($"PID={candidate.Id}, 内存={SafeRead(() => candidate.WorkingSet64 / 1024.0 / 1024.0, 0):F0} MB, 窗口={SafeRead(() => candidate.MainWindowTitle, string.Empty)}");
                }

                Console.Write("请输入目标 PID：");
                if (int.TryParse(Console.ReadLine(), out int selectedId) && processes.Any(process => process.Id == selectedId))
                {
                    return processes.First(process => process.Id == selectedId);
                }

                Console.WriteLine("PID 无效，请重新选择。");
            }

            await Task.Delay(1000);
        }
    }

    private static double CalculateCpuPercent(TimeSpan previous, TimeSpan current, double elapsedSeconds)
    {
        if (elapsedSeconds <= 0) return 0;
        double value = (current - previous).TotalSeconds / elapsedSeconds / Environment.ProcessorCount * 100.0;
        return Math.Clamp(value, 0, 100);
    }

    private static T SafeRead<T>(Func<T> action, T fallback)
    {
        try { return action(); }
        catch { return fallback; }
    }

    private static string EscapeCsv(string value) =>
        value.IndexOfAny([',', '"', '\r', '\n']) < 0 ? value : $"\"{value.Replace("\"", "\"\"")}\"";

    private static string MakeSafeFileName(string value)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        return new string(value.Select(character => invalid.Contains(character) ? '_' : character).ToArray());
    }

    private static void PrintUsage()
    {
        Console.WriteLine("用法: dotnet run --project CS2BaselineLogger -- [参数]");
        Console.WriteLine("  --experiment <名称>             实验名称（必填）");
        Console.WriteLine("  --cheat <true|false>            实验标签（必填）");
        Console.WriteLine("  --pid <PID>                     指定目标进程，可选");
        Console.WriteLine("  --process <名称>                目标进程，默认 cs2");
        Console.WriteLine("  --interval-ms <毫秒>            采样间隔，默认 100");
        Console.WriteLine("  --duration-seconds <秒>         自动停止时长，可选");
        Console.WriteLine("  --module-snapshot-seconds <秒>  模块快照间隔，默认 10");
        Console.WriteLine("  --output <目录>                 输出根目录，默认 ./data");
        Console.WriteLine("  --map <地图> --mode <模式> --bots <数量> --notes <说明>");
        Console.WriteLine("  --help                          显示帮助");
    }
}

internal sealed record ExperimentMetadata(
    string RunId,
    string Experiment,
    bool CheatEnabled,
    string Map,
    string Mode,
    int BotCount,
    string Notes,
    int ProcessId,
    string ProcessName,
    DateTime StartedUtc,
    int SampleIntervalMs,
    int ModuleSnapshotSeconds,
    int? DurationSeconds,
    string MachineName,
    string OperatingSystem,
    int LogicalProcessorCount);

internal sealed record LoggerOptions(
    string Experiment,
    bool CheatEnabled,
    int? ProcessId,
    string ProcessName,
    int SampleIntervalMs,
    int ModuleSnapshotSeconds,
    int? DurationSeconds,
    string OutputDirectory,
    string Map,
    string Mode,
    int BotCount,
    string Notes)
{
    public static bool TryParse(string[] args, out LoggerOptions? options, out string? error)
    {
        options = null;
        error = null;
        if (args.Any(value => value is "--help" or "-h")) return false;

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

        if (!values.TryGetValue("--experiment", out string? experiment) || string.IsNullOrWhiteSpace(experiment))
        {
            error = "缺少必填参数 --experiment。";
            return false;
        }

        if (!values.TryGetValue("--cheat", out string? cheatText) || !bool.TryParse(cheatText, out bool cheat))
        {
            error = "--cheat 必须是 true 或 false。";
            return false;
        }

        if (!TryOptionalPositiveInt(values, "--pid", out int? pid, out error) ||
            !TryPositiveInt(values, "--interval-ms", 100, out int interval, out error) ||
            !TryPositiveInt(values, "--module-snapshot-seconds", 10, out int moduleInterval, out error) ||
            !TryOptionalPositiveInt(values, "--duration-seconds", out int? duration, out error) ||
            !TryNonNegativeInt(values, "--bots", 0, out int bots, out error))
        {
            return false;
        }

        HashSet<string> known = new(StringComparer.OrdinalIgnoreCase)
        {
            "--experiment", "--cheat", "--pid", "--process", "--interval-ms",
            "--module-snapshot-seconds", "--duration-seconds", "--output",
            "--map", "--mode", "--bots", "--notes"
        };
        string? unknown = values.Keys.FirstOrDefault(key => !known.Contains(key));
        if (unknown is not null)
        {
            error = $"未知参数：{unknown}";
            return false;
        }

        options = new LoggerOptions(
            experiment.Trim(), cheat, pid, Get(values, "--process", "cs2"), interval,
            moduleInterval, duration, Get(values, "--output", "data"),
            Get(values, "--map", "unknown"), Get(values, "--mode", "unknown"),
            bots, Get(values, "--notes", string.Empty));
        return true;
    }

    private static string Get(Dictionary<string, string> values, string key, string fallback) =>
        values.TryGetValue(key, out string? value) ? value : fallback;

    private static bool TryPositiveInt(Dictionary<string, string> values, string key, int fallback, out int result, out string? error)
    {
        error = null;
        if (!values.TryGetValue(key, out string? text)) { result = fallback; return true; }
        if (int.TryParse(text, out result) && result > 0) return true;
        error = $"{key} 必须是正整数。";
        return false;
    }

    private static bool TryOptionalPositiveInt(Dictionary<string, string> values, string key, out int? result, out string? error)
    {
        result = null;
        error = null;
        if (!values.TryGetValue(key, out string? text)) return true;
        if (int.TryParse(text, out int parsed) && parsed > 0) { result = parsed; return true; }
        error = $"{key} 必须是正整数。";
        return false;
    }

    private static bool TryNonNegativeInt(Dictionary<string, string> values, string key, int fallback, out int result, out string? error)
    {
        error = null;
        if (!values.TryGetValue(key, out string? text)) { result = fallback; return true; }
        if (int.TryParse(text, out result) && result >= 0) return true;
        error = $"{key} 必须是非负整数。";
        return false;
    }
}
