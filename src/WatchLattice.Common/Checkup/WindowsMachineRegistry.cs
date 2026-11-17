using System.Runtime.Versioning;
using Microsoft.Win32;

namespace WatchLattice.Common.Checkup;

/// <summary>Reads HKEY_LOCAL_MACHINE through the 64-bit view, read-only. Opening a key never asks for write access.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMachineRegistry : IMachineRegistry
{
    public object? Read(string key, string name)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var sub = root.OpenSubKey(key, writable: false);
        return sub?.GetValue(name);
    }

    public bool KeyExists(string key)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var sub = root.OpenSubKey(key, writable: false);
        return sub is not null;
    }
}
