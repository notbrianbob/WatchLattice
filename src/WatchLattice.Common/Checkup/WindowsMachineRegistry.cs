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

/// <summary>For non-Windows builds and tests: every read says the registry isn't there, so each check comes out Unknown.</summary>
public sealed class NoMachineRegistry : IMachineRegistry
{
    public object? Read(string key, string name) => throw new PlatformNotSupportedException("The registry is only on Windows.");

    public bool KeyExists(string key) => throw new PlatformNotSupportedException("The registry is only on Windows.");
}
