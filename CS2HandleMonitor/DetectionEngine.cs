namespace CS2HandleMonitor;

internal sealed record DetectionDecision(
    int RawRiskScore,
    int AdjustedRiskScore,
    string Classification,
    string RiskReasons,
    bool IsDetection);

internal static class DetectionEngine
{
    internal static DetectionDecision Evaluate(
        TargetIdentity target,
        TargetHandle handle,
        int threshold)
    {
        List<string> reasons = [];
        if (handle.AccessRights.Contains("VM_READ", StringComparison.Ordinal)) reasons.Add("VM_READ");
        if (handle.AccessRights.Contains("VM_WRITE", StringComparison.Ordinal)) reasons.Add("VM_WRITE");
        if (handle.AccessRights.Contains("VM_OPERATION", StringComparison.Ordinal)) reasons.Add("VM_OPERATION");
        if (handle.AccessRights.Contains("CREATE_THREAD", StringComparison.Ordinal)) reasons.Add("CREATE_THREAD");
        if (!handle.HasEmbeddedSignature) reasons.Add("NO_EMBEDDED_SIGNATURE");

        int adjustedRisk = handle.RiskScore;
        string classification = "UnclassifiedExternalProcess";

        if (IsDedicatedServerConsoleHost(target, handle))
        {
            adjustedRisk = 5;
            classification = "ExpectedDedicatedServerConsoleHost";
            reasons.Add("PARENT_IS_TARGET");
            reasons.Add("SYSTEM_CONHOST_PATH");
        }
        else if (DetectionPolicy.IsCalibrationAllowlisted(handle))
        {
            adjustedRisk = DetectionPolicy.AllowlistedRiskScore;
            classification = "CalibrationAllowlistedSignedProcess";
            reasons.Add("CALIBRATION_SHA256_ALLOWLIST");
        }
        else if (adjustedRisk < threshold)
        {
            classification = "LowRiskObserver";
        }
        else
        {
            classification = "SuspiciousProcessHandle";
        }

        return new DetectionDecision(
            handle.RiskScore,
            adjustedRisk,
            classification,
            string.Join('|', reasons),
            adjustedRisk >= threshold);
    }

    private static bool IsDedicatedServerConsoleHost(TargetIdentity target, TargetHandle handle)
    {
        if (!string.Equals(target.Role, "DedicatedServer", StringComparison.Ordinal)) return false;
        if (!string.Equals(handle.SourceProcessName, "conhost", StringComparison.OrdinalIgnoreCase)) return false;
        if (handle.ParentProcessId != target.ProcessId) return false;

        string expectedPath = Path.GetFullPath(Path.Combine(Environment.SystemDirectory, "conhost.exe"));
        try
        {
            return string.Equals(
                Path.GetFullPath(handle.SourceImagePath),
                expectedPath,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
