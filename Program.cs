using System.Diagnostics;
using System.Globalization;
using System.Text;

internal static class Program
{
    private const string TargetProcessName = "cs2";
    private const int SampleIntervalMs = 100;

    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        string experimentName = GetArgument(
            args,
            "--experiment",
            $"baseline_{DateTime.Now:yyyyMMdd_HHmmss}");

        bool cheatEnabled = bool.TryParse(
            GetArgument(args, "--cheat", "false"),
            out bool cheatValue) && cheatValue;

        string outputDirectory = Path.Combine(
            AppContext.BaseDirectory,
            "logs");

        Directory.CreateDirectory(outputDirectory);

        string safeExperimentName = MakeSafeFileName(experimentName);

        string outputPath = Path.Combine(
            outputDirectory,
            $"{safeExperimentName}.csv");

        Console.WriteLine("CS2 Baseline Logger");
        Console.WriteLine($"Experiment: {experimentName}");
        Console.WriteLine($"Cheat enabled label: {cheatEnabled}");
        Console.WriteLine($"Sampling interval: {SampleIntervalMs} ms");
        Console.WriteLine($"Output: {outputPath}");
        Console.WriteLine();

        Process? process = await WaitForProcessAsync(TargetProcessName);

        if (process is null)
        {
            Console.Error.WriteLine("No CS2 process was found.");
            return 1;
        }

        Console.WriteLine(
            $"Connected to CS2: PID={process.Id}");

        Console.WriteLine(
            "Press Ctrl+C to stop recording.");

        using CancellationTokenSource cancellationSource = new();

        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellationSource.Cancel();
        };

        try
        {
            await RecordProcessAsync(
                process,
                outputPath,
                experimentName,
                cheatEnabled,
                cancellationSource.Token);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                $"Recording failed: {exception.Message}");

            return 1;
        }

        Console.WriteLine();
        Console.WriteLine("Recording has ended.");
        Console.WriteLine($"CSV file: {outputPath}");

        return 0;
    }

    private static async Task RecordProcessAsync(
        Process process,
        string outputPath,
        string experimentName,
        bool cheatEnabled,
        CancellationToken cancellationToken)
    {
        await using FileStream fileStream = new(
            outputPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.Read);

        await using StreamWriter writer = new(
            fileStream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        await writer.WriteLineAsync(
            "TimestampUtc," +
            "ElapsedMs," +
            "Experiment," +
            "CheatEnabled," +
            "ProcessId," +
            "CpuPercent," +
            "WorkingSetMB," +
            "PrivateMemoryMB," +
            "ThreadCount," +
            "HandleCount," +
            "ModuleCount," +
            "Responding");

        Stopwatch experimentTimer = Stopwatch.StartNew();
        Stopwatch cpuTimer = Stopwatch.StartNew();

        TimeSpan previousCpuTime = process.TotalProcessorTime;
        long sampleNumber = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            if (process.HasExited)
            {
                Console.WriteLine("CS2 has exited; stopping recording.");
                break;
            }

            process.Refresh();

            TimeSpan currentCpuTime = process.TotalProcessorTime;
            double elapsedCpuSeconds = cpuTimer.Elapsed.TotalSeconds;

            double cpuPercent = CalculateCpuPercent(
                previousCpuTime,
                currentCpuTime,
                elapsedCpuSeconds);

            previousCpuTime = currentCpuTime;
            cpuTimer.Restart();

            double workingSetMb =
                process.WorkingSet64 / 1024.0 / 1024.0;

            double privateMemoryMb =
                process.PrivateMemorySize64 / 1024.0 / 1024.0;

            int threadCount = SafeRead(
                () => process.Threads.Count,
                -1);

            int handleCount = SafeRead(
                () => process.HandleCount,
                -1);

            int moduleCount = SafeRead(
                () => process.Modules.Count,
                -1);

            bool responding = SafeRead(
                () => process.Responding,
                false);

            string csvLine = string.Join(",",
                DateTime.UtcNow.ToString(
                    "O",
                    CultureInfo.InvariantCulture),

                experimentTimer.ElapsedMilliseconds.ToString(
                    CultureInfo.InvariantCulture),

                EscapeCsv(experimentName),

                cheatEnabled
                    ? "true"
                    : "false",

                process.Id.ToString(
                    CultureInfo.InvariantCulture),

                cpuPercent.ToString(
                    "F4",
                    CultureInfo.InvariantCulture),

                workingSetMb.ToString(
                    "F4",
                    CultureInfo.InvariantCulture),

                privateMemoryMb.ToString(
                    "F4",
                    CultureInfo.InvariantCulture),

                threadCount.ToString(
                    CultureInfo.InvariantCulture),

                handleCount.ToString(
                    CultureInfo.InvariantCulture),

                moduleCount.ToString(
                    CultureInfo.InvariantCulture),

                responding
                    ? "true"
                    : "false");

            await writer.WriteLineAsync(csvLine);

            sampleNumber++;

            // Flush to disk every 10 samples, approximately once per second.
            if (sampleNumber % 10 == 0)
            {
                await writer.FlushAsync();

                Console.Write(
                    $"\rTime: {experimentTimer.Elapsed:mm\\:ss}  " +
                    $"CPU: {cpuPercent:F1}%  " +
                    $"Memory: {workingSetMb:F0} MB  " +
                    $"Threads: {threadCount}  " +
                    $"Handles: {handleCount}   ");
            }

            await Task.Delay(
                SampleIntervalMs,
                cancellationToken);
        }

        await writer.FlushAsync();
    }

    private static double CalculateCpuPercent(
        TimeSpan previousCpuTime,
        TimeSpan currentCpuTime,
        double elapsedSeconds)
    {
        if (elapsedSeconds <= 0)
        {
            return 0;
        }

        double cpuUsedSeconds =
            (currentCpuTime - previousCpuTime).TotalSeconds;

        double cpuPercent =
            cpuUsedSeconds /
            elapsedSeconds /
            Environment.ProcessorCount *
            100.0;

        return Math.Clamp(cpuPercent, 0, 100);
    }

    private static async Task<Process?> WaitForProcessAsync(
        string processName)
    {
        Console.WriteLine(
            $"Waiting for process {processName}.exe...");

        while (true)
        {
            Process[] processes =
                Process.GetProcessesByName(processName);

            if (processes.Length > 0)
            {
                return processes
                    .OrderByDescending(
                        process => process.WorkingSet64)
                    .First();
            }

            await Task.Delay(1000);
        }
    }

    private static T SafeRead<T>(
        Func<T> action,
        T fallback)
    {
        try
        {
            return action();
        }
        catch
        {
            return fallback;
        }
    }

    private static string GetArgument(
        string[] args,
        string name,
        string defaultValue)
    {
        for (int index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(
                args[index],
                name,
                StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return defaultValue;
    }

    private static string EscapeCsv(string value)
    {
        if (!value.Contains(',') &&
            !value.Contains('"') &&
            !value.Contains('\n'))
        {
            return value;
        }

        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static string MakeSafeFileName(string value)
    {
        char[] invalidCharacters =
            Path.GetInvalidFileNameChars();

        return new string(
            value.Select(character =>
                invalidCharacters.Contains(character)
                    ? '_'
                    : character)
                .ToArray());
    }
}
