using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CS2HandleMonitor;

internal sealed record TargetHandle(
    int SourceProcessId,
    string SourceProcessName,
    string SourceImagePath,
    int ParentProcessId,
    string SourceStartedUtc,
    string SourceSha256,
    bool HasEmbeddedSignature,
    string CertificateSubject,
    ulong HandleValue,
    uint GrantedAccess,
    string AccessRights,
    int RiskScore);

internal sealed record HandleScanResult(
    IReadOnlyList<TargetHandle> Handles,
    int SystemHandleCount,
    int SourceProcessesInspected,
    int SourceProcessesDenied,
    int DuplicateFailures);

internal static class SystemHandleScanner
{
    private const int InitialBufferSize = 1024 * 1024;
    private const int MaximumBufferSize = 256 * 1024 * 1024;

    internal static HandleScanResult FindHandlesToProcess(int targetProcessId)
    {
        SystemHandleTableEntryInfoEx[] systemHandles = QuerySystemHandles();
        List<TargetHandle> matches = [];
        int inspected = 0;
        int denied = 0;
        int duplicateFailures = 0;
        int ownProcessId = Environment.ProcessId;
        IntPtr currentProcess = NativeMethods.GetCurrentProcess();

        foreach (IGrouping<int, SystemHandleTableEntryInfoEx> sourceGroup in systemHandles
                     .Where(entry => ToProcessId(entry.UniqueProcessId) > 0)
                     .GroupBy(entry => ToProcessId(entry.UniqueProcessId)))
        {
            int sourceProcessId = sourceGroup.Key;
            // The target process normally owns a full-access pseudo/self handle.
            // It is not an external observer and must not contribute to risk.
            if (sourceProcessId == ownProcessId || sourceProcessId == targetProcessId)
            {
                continue;
            }

            IntPtr sourceProcess = NativeMethods.OpenProcess(
                NativeMethods.ProcessDuplicateHandle | NativeMethods.ProcessQueryLimitedInformation,
                inheritHandle: false,
                sourceProcessId);

            if (sourceProcess == IntPtr.Zero)
            {
                sourceProcess = NativeMethods.OpenProcess(
                    NativeMethods.ProcessDuplicateHandle,
                    inheritHandle: false,
                    sourceProcessId);
            }

            if (sourceProcess == IntPtr.Zero)
            {
                denied++;
                continue;
            }

            inspected++;
            try
            {
                foreach (SystemHandleTableEntryInfoEx entry in sourceGroup)
                {
                    if (!NativeMethods.DuplicateHandle(
                            sourceProcess,
                            ToIntPtr(entry.HandleValue),
                            currentProcess,
                            out IntPtr duplicate,
                            0,
                            inheritHandle: false,
                            NativeMethods.DuplicateSameAccess))
                    {
                        duplicateFailures++;
                        continue;
                    }

                    try
                    {
                        if (NativeMethods.GetProcessId(duplicate) != targetProcessId)
                        {
                            continue;
                        }

                        SourceProcessIdentity identity = ProcessIdentityInspector.Read(sourceProcessId, sourceProcess);
                        matches.Add(new TargetHandle(
                            sourceProcessId,
                            identity.Name,
                            identity.ImagePath,
                            identity.ParentProcessId,
                            identity.StartedUtc,
                            identity.Sha256,
                            identity.HasEmbeddedSignature,
                            identity.CertificateSubject,
                            entry.HandleValue.ToUInt64(),
                            entry.GrantedAccess,
                            ProcessAccessRights.Describe(entry.GrantedAccess),
                            ProcessAccessRights.Score(entry.GrantedAccess)));
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(duplicate);
                    }
                }
            }
            finally
            {
                NativeMethods.CloseHandle(sourceProcess);
            }
        }

        return new HandleScanResult(
            matches.OrderByDescending(handle => handle.RiskScore)
                .ThenBy(handle => handle.SourceProcessId)
                .ThenBy(handle => handle.HandleValue)
                .ToArray(),
            systemHandles.Length,
            inspected,
            denied,
            duplicateFailures);
    }

    private static SystemHandleTableEntryInfoEx[] QuerySystemHandles()
    {
        int bufferSize = InitialBufferSize;
        while (bufferSize <= MaximumBufferSize)
        {
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                int status = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SystemExtendedHandleInformation,
                    buffer,
                    bufferSize,
                    out int requiredLength);

                if (status == NativeMethods.StatusInfoLengthMismatch)
                {
                    bufferSize = Math.Max(bufferSize * 2, requiredLength + 64 * 1024);
                    continue;
                }

                if (status < 0)
                {
                    throw new Win32Exception(status, $"NtQuerySystemInformation failed: 0x{status:X8}");
                }

                ulong countValue = unchecked((ulong)Marshal.ReadInt64(buffer));
                if (countValue > int.MaxValue)
                {
                    throw new InvalidOperationException("系统句柄数量超出支持范围。");
                }

                int count = (int)countValue;
                int entrySize = Marshal.SizeOf<SystemHandleTableEntryInfoEx>();
                IntPtr entryPointer = IntPtr.Add(buffer, IntPtr.Size * 2);
                SystemHandleTableEntryInfoEx[] entries = new SystemHandleTableEntryInfoEx[count];
                for (int index = 0; index < count; index++)
                {
                    entries[index] = Marshal.PtrToStructure<SystemHandleTableEntryInfoEx>(entryPointer);
                    entryPointer = IntPtr.Add(entryPointer, entrySize);
                }

                return entries;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new InvalidOperationException("系统句柄缓冲区超过安全上限。");
    }

    private static int ToProcessId(UIntPtr value) =>
        value.ToUInt64() <= int.MaxValue ? (int)value.ToUInt64() : -1;

    private static IntPtr ToIntPtr(UIntPtr value) =>
        unchecked((IntPtr)(long)value.ToUInt64());

}
