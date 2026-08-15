namespace CS2HandleMonitor;

internal static class ProcessAccessRights
{
    private const uint Terminate = 0x0001;
    private const uint CreateThread = 0x0002;
    private const uint VmOperation = 0x0008;
    private const uint VmRead = 0x0010;
    private const uint VmWrite = 0x0020;
    private const uint DuplicateHandle = 0x0040;
    private const uint CreateProcess = 0x0080;
    private const uint SetQuota = 0x0100;
    private const uint SetInformation = 0x0200;
    private const uint QueryInformation = 0x0400;
    private const uint SuspendResume = 0x0800;
    private const uint QueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;

    private static readonly (uint Mask, string Name)[] KnownRights =
    [
        (Terminate, "TERMINATE"),
        (CreateThread, "CREATE_THREAD"),
        (VmOperation, "VM_OPERATION"),
        (VmRead, "VM_READ"),
        (VmWrite, "VM_WRITE"),
        (DuplicateHandle, "DUP_HANDLE"),
        (CreateProcess, "CREATE_PROCESS"),
        (SetQuota, "SET_QUOTA"),
        (SetInformation, "SET_INFORMATION"),
        (QueryInformation, "QUERY_INFORMATION"),
        (SuspendResume, "SUSPEND_RESUME"),
        (QueryLimitedInformation, "QUERY_LIMITED_INFORMATION"),
        (Synchronize, "SYNCHRONIZE")
    ];

    internal static string Describe(uint access)
    {
        string[] names = KnownRights
            .Where(right => (access & right.Mask) != 0)
            .Select(right => right.Name)
            .ToArray();
        return names.Length == 0 ? "OTHER" : string.Join('|', names);
    }

    internal static int Score(uint access)
    {
        int score = 0;
        if ((access & VmRead) != 0) score += 40;
        if ((access & VmWrite) != 0) score += 25;
        if ((access & VmOperation) != 0) score += 15;
        if ((access & CreateThread) != 0) score += 25;
        if ((access & DuplicateHandle) != 0) score += 10;
        if ((access & (QueryInformation | QueryLimitedInformation)) != 0) score += 5;
        return Math.Min(score, 100);
    }
}
