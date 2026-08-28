using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

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
            Console.Error.WriteLine($"Target process {parsedOptions.ProcessName}.exe was not found.");
            return 1;
        }

        DateTime trialStartUtc = DateTime.UtcNow;
        TrialMetadata metadata;
        try
        {
            metadata = TrialMetadata.LoadOrCreate(parsedOptions.TrialMetadataPath, trialStartUtc);
            metadata = metadata with
            {
                DetectionThreshold = parsedOptions.DetectionThreshold,
                PolicyVersion = DetectionPolicy.Version
            };
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            Console.Error.WriteLine($"Invalid trial metadata: {exception.Message}");
            return 2;
        }

        string runId = $"{SanitizePathComponent(metadata.TrialId)}_{trialStartUtc:yyyyMMdd_HHmmss}";
        string outputDirectory = Path.Combine(Path.GetFullPath(parsedOptions.OutputDirectory), runId);
        Directory.CreateDirectory(outputDirectory);
        string metadataPath = Path.Combine(outputDirectory, "metadata.json");
        await metadata.WriteAsync(metadataPath);
        string outputPath = Path.Combine(outputDirectory, "handles.csv");
        string summaryPath = Path.Combine(outputDirectory, "scan_summary.csv");
        string eventsPath = Path.Combine(outputDirectory, "handle_events.csv");
        string detectionsPath = Path.Combine(outputDirectory, "detections.csv");

        Console.WriteLine("CS2 Handle Monitor");
        Console.WriteLine(parsedOptions.ProcessId is null
            ? $"Mode: automatically monitor all {parsedOptions.ProcessName}.exe instances"
            : $"Mode: monitor PID {parsedOptions.ProcessId} only");
        foreach (TargetIdentity target in initialTargets) PrintTarget(target);
        Console.WriteLine($"Interval: {parsedOptions.IntervalSeconds} seconds");
        Console.WriteLine($"Detection threshold: {parsedOptions.DetectionThreshold}");
        Console.WriteLine($"Detection policy: {DetectionPolicy.Version}");
        Console.WriteLine($"Trial ID: {metadata.TrialId}");
        Console.WriteLine($"Expected label: {metadata.ExpectedLabel}");
        Console.WriteLine($"Output directory: {outputDirectory}");
        Console.WriteLine("Tip: Run as administrator to improve handle visibility. Press Ctrl+C to stop.");

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
            await MonitorAsync(
                parsedOptions, metadata, outputPath, summaryPath, eventsPath, detectionsPath, stopSource.Token);
        }
        catch (OperationCanceledException) { }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Monitoring failed: {exception.Message}");
            return 1;
        }

        metadata = metadata with { TrialEndTimeUtc = DateTime.UtcNow };
        await metadata.WriteAsync(metadataPath);

        Console.WriteLine();
        Console.WriteLine($"Handle records: {outputPath}");
        Console.WriteLine($"Scan summary: {summaryPath}");
        Console.WriteLine($"Lifecycle events: {eventsPath}");
        Console.WriteLine($"Detection alerts: {detectionsPath}");
        Console.WriteLine($"Trial metadata: {metadataPath}");
        return 0;
    }

    private static async Task MonitorAsync(
        MonitorOptions options,
        TrialMetadata metadata,
        string outputPath,
        string summaryPath,
        string eventsPath,
        string detectionsPath,
        CancellationToken cancellationToken)
    {
        string trialId = metadata.TrialId;
        await using StreamWriter writer = CreateWriter(outputPath);
        await writer.WriteLineAsync(
            "TrialId,TimestampUtc,ScanNumber,ElapsedMs,TargetProcessId,TargetProcessName,TargetImagePath,TargetWindowTitle,TargetRole,SourceProcessId,SourceProcessName,SourceImagePath,ParentProcessId,SourceStartedUtc,SourceSha256,HasEmbeddedSignature,CertificateSubject,HandleValue,GrantedAccess,AccessRights,RawRiskScore,AdjustedRiskScore,Classification,RiskReasons,AlertStatus,SystemHandleCount,SourceProcessesInspected,SourceProcessesDenied,DuplicateFailures");

        await using StreamWriter summaryWriter = CreateWriter(summaryPath);
        await summaryWriter.WriteLineAsync(
            "TrialId,TimestampUtc,ScanNumber,ElapsedMs,TargetProcessId,TargetProcessName,TargetImagePath,TargetWindowTitle,TargetRole,MatchedExternalHandles,HighRiskHandles,SystemHandleCount,SourceProcessesInspected,SourceProcessesDenied,DuplicateFailures,ScanDurationMs,MonitorCpuPercent,MonitorWorkingSetMb,MonitorPrivateMemoryMb");

        await using StreamWriter eventsWriter = CreateWriter(eventsPath);
        await eventsWriter.WriteLineAsync(
            "TrialId,TimestampUtc,ScanNumber,ElapsedMs,Event,DurationMs,TargetProcessId,TargetRole,SourceProcessId,SourceProcessName,SourceImagePath,ParentProcessId,SourceStartedUtc,SourceSha256,HasEmbeddedSignature,CertificateSubject,HandleValue,GrantedAccess,AccessRights,RawRiskScore,AdjustedRiskScore,Classification,RiskReasons,AlertStatus");

        await using StreamWriter detectionsWriter = CreateWriter(detectionsPath);
        await detectionsWriter.WriteLineAsync(
            "TrialId,TimestampUtc,ScanNumber,ElapsedMs,DetectionLatencyMs,TargetProcessId,TargetRole,SourceProcessId,SourceProcessName,SourceImagePath,ParentProcessId,SourceSha256,HasEmbeddedSignature,CertificateSubject,HandleValue,GrantedAccess,AccessRights,RawRiskScore,AdjustedRiskScore,Classification,RiskReasons,AlertStatus");

        Stopwatch timer = Stopwatch.StartNew();
        using Process monitorProcess = Process.GetCurrentProcess();
        Dictionary<HandleKey, ActiveHandle> activeHandles = [];
        using PeriodicTimer scanTimer = new(TimeSpan.FromSeconds(options.IntervalSeconds));
        int scanNumber = 0;
        do
        {
            scanNumber++;
            Stopwatch scanStopwatch = Stopwatch.StartNew();
            TimeSpan scanStartCpu = monitorProcess.TotalProcessorTime;
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
                        EscapeCsv(trialId),
                        timestamp,
                        scanNumber.ToString(CultureInfo.InvariantCulture),
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
                        decision.IsDetection ? "true" : "false",
                        result.SystemHandleCount.ToString(CultureInfo.InvariantCulture),
                        result.SourceProcessesInspected.ToString(CultureInfo.InvariantCulture),
                        result.SourceProcessesDenied.ToString(CultureInfo.InvariantCulture),
                        result.DuplicateFailures.ToString(CultureInfo.InvariantCulture)));

                    if (!activeHandles.ContainsKey(key))
                    {
                        ActiveHandle opened = new(target, handle, decision, DateTime.UtcNow, elapsedMs);
                        activeHandles.Add(key, opened);
                        await WriteHandleEventAsync(
                            eventsWriter, trialId, scanNumber, "Opened", opened, DateTime.UtcNow, elapsedMs);
                        if (decision.IsDetection)
                        {
                            await WriteDetectionAsync(
                                detectionsWriter,
                                trialId,
                                scanNumber,
                                metadata.FeatureEnableTimeUtc ?? metadata.ApplicationStartTimeUtc,
                                target,
                                handle,
                                decision,
                                DateTime.UtcNow,
                                elapsedMs);
                            Console.WriteLine();
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[DETECTED] {handle.SourceProcessName}.exe PID={handle.SourceProcessId} -> {target.ProcessName}.exe PID={target.ProcessId}  Risk={decision.AdjustedRiskScore}");
                            Console.ResetColor();
                        }
                    }
                }

                monitorProcess.Refresh();
                double monitorCpuPercent = scanStopwatch.Elapsed.TotalMilliseconds <= 0
                    ? 0
                    : (monitorProcess.TotalProcessorTime - scanStartCpu).TotalMilliseconds /
                      scanStopwatch.Elapsed.TotalMilliseconds / Environment.ProcessorCount * 100;

                await summaryWriter.WriteLineAsync(string.Join(',',
                    EscapeCsv(trialId),
                    timestamp,
                    scanNumber.ToString(CultureInfo.InvariantCulture),
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
                    result.DuplicateFailures.ToString(CultureInfo.InvariantCulture),
                    scanStopwatch.Elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture),
                    monitorCpuPercent.ToString("F3", CultureInfo.InvariantCulture),
                    (monitorProcess.WorkingSet64 / 1048576d).ToString("F3", CultureInfo.InvariantCulture),
                    (monitorProcess.PrivateMemorySize64 / 1048576d).ToString("F3", CultureInfo.InvariantCulture)));
            }

            foreach (HandleKey closedKey in activeHandles.Keys.Where(key => !currentHandles.Contains(key)).ToArray())
            {
                ActiveHandle closed = activeHandles[closedKey];
                await WriteHandleEventAsync(
                    eventsWriter, trialId, scanNumber, "Closed", closed, DateTime.UtcNow, elapsedMs);
                activeHandles.Remove(closedKey);
            }

            await writer.FlushAsync(cancellationToken);
            await summaryWriter.FlushAsync(cancellationToken);
            await eventsWriter.FlushAsync(cancellationToken);
            await detectionsWriter.FlushAsync(cancellationToken);
            Console.Write($"\r{timer.Elapsed:mm\\:ss}  Targets: {targets.Length}  External handles: {totalMatches}  High risk: {totalHighRisk}  Inaccessible processes: {maximumDenied}   ");
        }
        while (await scanTimer.WaitForNextTickAsync(cancellationToken));
    }

    private static async Task WriteDetectionAsync(
        StreamWriter writer,
        string trialId,
        int scanNumber,
        DateTime? referenceTimeUtc,
        TargetIdentity target,
        TargetHandle handle,
        DetectionDecision decision,
        DateTime observedUtc,
        long elapsedMs)
    {
        string detectionLatencyMs = referenceTimeUtc is DateTime reference
            ? Math.Max(0, (observedUtc - reference).TotalMilliseconds).ToString("F3", CultureInfo.InvariantCulture)
            : string.Empty;
        await writer.WriteLineAsync(string.Join(',',
            EscapeCsv(trialId),
            observedUtc.ToString("O", CultureInfo.InvariantCulture),
            scanNumber.ToString(CultureInfo.InvariantCulture),
            elapsedMs.ToString(CultureInfo.InvariantCulture),
            detectionLatencyMs,
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
            EscapeCsv(decision.RiskReasons),
            "true"));
    }

    private static async Task WriteHandleEventAsync(
        StreamWriter writer,
        string trialId,
        int scanNumber,
        string eventName,
        ActiveHandle active,
        DateTime observedUtc,
        long elapsedMs)
    {
        TargetHandle handle = active.Handle;
        DetectionDecision decision = active.Decision;
        await writer.WriteLineAsync(string.Join(',',
            EscapeCsv(trialId),
            observedUtc.ToString("O", CultureInfo.InvariantCulture),
            scanNumber.ToString(CultureInfo.InvariantCulture),
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
            EscapeCsv(decision.RiskReasons),
            decision.IsDetection ? "true" : "false"));
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
        Console.WriteLine($"Target: PID {target.ProcessId}, Role {target.Role}, Window {target.WindowTitle}");

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

    private static string SanitizePathComponent(string value)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        string sanitized = new(value.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "trial" : sanitized;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: dotnet run --project CS2HandleMonitor -- [options]");
        Console.WriteLine("  --pid <PID>                 Monitor only this PID; omit to monitor all processes with the same name");
        Console.WriteLine("  --process <name>            Target process name; default: cs2");
        Console.WriteLine("  --interval-seconds <seconds>  Scan interval; default: 2");
        Console.WriteLine("  --duration-seconds <seconds>  Automatic stop duration (optional)");
        Console.WriteLine($"  --threshold <0-100>         Real-time detection threshold; default: {DetectionPolicy.DefaultThreshold}");
        Console.WriteLine("  --trial-metadata <json>     Ground-truth trial metadata JSON");
        Console.WriteLine("  --output <directory>        Output root directory; default: ./data");
        Console.WriteLine("  --help                      Show help");
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
    string OutputDirectory,
    string? TrialMetadataPath)
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
                error = $"Invalid argument format: {args[index]}";
                return false;
            }
            values[args[index]] = args[index + 1];
        }

        HashSet<string> known = new(StringComparer.OrdinalIgnoreCase)
            { "--pid", "--process", "--interval-seconds", "--duration-seconds", "--threshold", "--output", "--trial-metadata" };
        string? unknown = values.Keys.FirstOrDefault(key => !known.Contains(key));
        if (unknown is not null) { error = $"Unknown argument: {unknown}"; return false; }

        if (!OptionalPositive(values, "--pid", out int? pid, out error) ||
            !Positive(values, "--interval-seconds", 2, out int interval, out error) ||
            !OptionalPositive(values, "--duration-seconds", out int? duration, out error) ||
            !Range(values, "--threshold", DetectionPolicy.DefaultThreshold, 0, 100, out int threshold, out error)) return false;

        options = new MonitorOptions(
            pid,
            values.GetValueOrDefault("--process", "cs2"),
            interval,
            duration,
            threshold,
            values.GetValueOrDefault("--output", "data"),
            values.GetValueOrDefault("--trial-metadata"));
        return true;
    }

    private static bool Positive(Dictionary<string, string> values, string key, int fallback, out int value, out string? error)
    {
        error = null;
        if (!values.TryGetValue(key, out string? text)) { value = fallback; return true; }
        if (int.TryParse(text, out value) && value > 0) return true;
        error = $"{key} must be a positive integer.";
        return false;
    }

    private static bool OptionalPositive(Dictionary<string, string> values, string key, out int? value, out string? error)
    {
        value = null;
        error = null;
        if (!values.TryGetValue(key, out string? text)) return true;
        if (int.TryParse(text, out int parsed) && parsed > 0) { value = parsed; return true; }
        error = $"{key} must be a positive integer.";
        return false;
    }

    private static bool Range(Dictionary<string, string> values, string key, int fallback, int minimum, int maximum, out int value, out string? error)
    {
        error = null;
        if (!values.TryGetValue(key, out string? text)) { value = fallback; return true; }
        if (int.TryParse(text, out value) && value >= minimum && value <= maximum) return true;
        error = $"{key} must be between {minimum} and {maximum}.";
        return false;
    }
}
