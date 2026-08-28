using System.Text.Json;

namespace CS2HandleMonitor;

internal sealed record FrozenPolicyData(
    string Version,
    int Threshold,
    int AllowlistedRiskScore,
    HashSet<string> TrustedProcessSha256);

internal static class DetectionPolicy
{
    private const string FileName = "frozen_detection_policy.json";
    private static readonly Lazy<FrozenPolicyData> Current = new(Load);

    internal static string Version => Current.Value.Version;
    internal static int DefaultThreshold => Current.Value.Threshold;
    internal static int AllowlistedRiskScore => Current.Value.AllowlistedRiskScore;

    internal static bool IsCalibrationAllowlisted(TargetHandle handle) =>
        handle.HasEmbeddedSignature &&
        !string.IsNullOrWhiteSpace(handle.SourceSha256) &&
        Current.Value.TrustedProcessSha256.Contains(handle.SourceSha256);

    private static FrozenPolicyData Load()
    {
        string path = Path.Combine(AppContext.BaseDirectory, FileName);
        using FileStream stream = File.OpenRead(path);
        using JsonDocument document = JsonDocument.Parse(stream);
        JsonElement root = document.RootElement;
        HashSet<string> hashes = root.GetProperty("trusted_process_sha256")
            .EnumerateArray()
            .Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item!.ToUpperInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new FrozenPolicyData(
            root.GetProperty("version").GetString() ?? "unknown",
            root.GetProperty("threshold").GetInt32(),
            root.GetProperty("allowlisted_risk_score").GetInt32(),
            hashes);
    }
}
