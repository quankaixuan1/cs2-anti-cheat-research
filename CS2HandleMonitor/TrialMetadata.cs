using System.Text;
using System.Text.Json;

namespace CS2HandleMonitor;

internal sealed record TrialMetadata(
    string TrialId,
    string Condition,
    string ApplicationName,
    string ApplicationCategory,
    bool? CheatEnabled,
    string EnabledFeature,
    DateTime? ApplicationStartTimeUtc,
    DateTime? FeatureEnableTimeUtc,
    DateTime TrialStartTimeUtc,
    DateTime? TrialEndTimeUtc,
    string ExpectedLabel,
    string Notes,
    int DetectionThreshold,
    string PolicyVersion)
{
    internal static TrialMetadata LoadOrCreate(string? path, DateTime trialStartUtc)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return new TrialMetadata(
                $"trial_{trialStartUtc:yyyyMMdd_HHmmss}",
                "unspecified",
                string.Empty,
                string.Empty,
                null,
                string.Empty,
                null,
                null,
                trialStartUtc,
                null,
                "unknown",
                "No trial metadata file was supplied.",
                0,
                "unfrozen");
        }

        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("Trial metadata file was not found.", fullPath);

        TrialMetadata? metadata = JsonSerializer.Deserialize<TrialMetadata>(
            File.ReadAllText(fullPath, Encoding.UTF8),
            JsonOptions());
        if (metadata is null)
            throw new InvalidDataException("Trial metadata JSON is empty or invalid.");

        string trialId = metadata.TrialId.Trim();
        if (string.IsNullOrWhiteSpace(trialId))
            throw new InvalidDataException("trial_id is required.");

        string expectedLabel = metadata.ExpectedLabel.Trim().ToLowerInvariant();
        if (expectedLabel is not ("benign" or "cheat" or "unknown"))
            throw new InvalidDataException("expected_label must be benign, cheat, or unknown.");

        if (metadata.CheatEnabled is true && expectedLabel == "benign" ||
            metadata.CheatEnabled is false && expectedLabel == "cheat")
            throw new InvalidDataException("cheat_enabled conflicts with expected_label.");

        return metadata with
        {
            TrialId = trialId,
            ExpectedLabel = expectedLabel,
            TrialStartTimeUtc = trialStartUtc,
            TrialEndTimeUtc = null
        };
    }

    internal Task WriteAsync(string path) =>
        File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(this, JsonOptions()),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

    private static JsonSerializerOptions JsonOptions() => new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true
    };
}
