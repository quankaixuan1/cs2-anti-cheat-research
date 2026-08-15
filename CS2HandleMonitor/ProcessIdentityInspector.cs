using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace CS2HandleMonitor;

internal sealed record SourceProcessIdentity(
    string Name,
    string ImagePath,
    int ParentProcessId,
    string StartedUtc,
    string Sha256,
    bool HasEmbeddedSignature,
    string CertificateSubject);

internal static class ProcessIdentityInspector
{
    private static readonly ConcurrentDictionary<string, SourceProcessIdentity> Cache = new();

    internal static SourceProcessIdentity Read(int processId, IntPtr processHandle)
    {
        string name = "unknown";
        string path = string.Empty;
        string startedUtc = string.Empty;

        try
        {
            using Process process = Process.GetProcessById(processId);
            name = SafeRead(() => process.ProcessName, "unknown");
            path = SafeRead(() => process.MainModule?.FileName ?? string.Empty, string.Empty);
            startedUtc = SafeRead(
                () => process.StartTime.ToUniversalTime().ToString("O"),
                string.Empty);
        }
        catch { }

        int parentProcessId = ReadParentProcessId(processHandle);
        string cacheKey = $"{processId}|{startedUtc}|{path}";
        return Cache.GetOrAdd(cacheKey, _ => BuildIdentity(
            name, path, parentProcessId, startedUtc));
    }

    private static SourceProcessIdentity BuildIdentity(
        string name,
        string path,
        int parentProcessId,
        string startedUtc)
    {
        string sha256 = string.Empty;
        bool hasSignature = false;
        string certificateSubject = string.Empty;

        if (!string.IsNullOrWhiteSpace(path))
        {
            try
            {
                using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                sha256 = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch { }

            try
            {
                using X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
                hasSignature = true;
                certificateSubject = certificate.Subject;
            }
            catch { }
        }

        return new SourceProcessIdentity(
            name,
            path,
            parentProcessId,
            startedUtc,
            sha256,
            hasSignature,
            certificateSubject);
    }

    private static int ReadParentProcessId(IntPtr processHandle)
    {
        int status = NativeMethods.NtQueryInformationProcess(
            processHandle,
            0,
            out ProcessBasicInformation information,
            Marshal.SizeOf<ProcessBasicInformation>(),
            out _);
        if (status < 0) return -1;
        long value = information.InheritedFromUniqueProcessId.ToInt64();
        return value is > 0 and <= int.MaxValue ? (int)value : -1;
    }

    private static T SafeRead<T>(Func<T> action, T fallback)
    {
        try { return action(); }
        catch { return fallback; }
    }
}
