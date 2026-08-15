using System.Runtime.InteropServices;

namespace CS2HandleMonitor;

internal static class NativeMethods
{
    internal const int SystemExtendedHandleInformation = 64;
    internal const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    internal const uint ProcessDuplicateHandle = 0x0040;
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint DuplicateSameAccess = 0x00000002;

    [DllImport("ntdll.dll")]
    internal static extern int NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        int systemInformationLength,
        out int returnLength);

    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        out ProcessBasicInformation processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DuplicateHandle(
        IntPtr sourceProcessHandle,
        IntPtr sourceHandle,
        IntPtr targetProcessHandle,
        out IntPtr targetHandle,
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetProcessId(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
}

[StructLayout(LayoutKind.Sequential)]
internal struct ProcessBasicInformation
{
    internal IntPtr Reserved1;
    internal IntPtr PebBaseAddress;
    internal IntPtr Reserved2_0;
    internal IntPtr Reserved2_1;
    internal IntPtr UniqueProcessId;
    internal IntPtr InheritedFromUniqueProcessId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SystemHandleTableEntryInfoEx
{
    internal IntPtr Object;
    internal UIntPtr UniqueProcessId;
    internal UIntPtr HandleValue;
    internal uint GrantedAccess;
    internal ushort CreatorBackTraceIndex;
    internal ushort ObjectTypeIndex;
    internal uint HandleAttributes;
    internal uint Reserved;
}
