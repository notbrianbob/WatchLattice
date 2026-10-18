using System.Runtime.Versioning;
using System.Security;
using Microsoft.Win32;

namespace WatchLattice.Persistence.Verification.Windows;

/// <summary>
/// Reads service configuration from HKLM\SYSTEM\CurrentControlSet\Services,
/// read-only. Values are read without expanding environment variables. The
/// Service Control Manager is not opened, so nothing can be started or
/// reconfigured. Key paths are built from a validated service name only.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceRegistry : IServiceSource
{
    public const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    public ServiceReadResult Read(string serviceName)
    {
        if (!ServiceAnalysis.IsValidServiceName(serviceName)) return new(ServiceReadStatus.Error, Error: "Not a valid service name.");
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var services = root.OpenSubKey(ServicesKey, writable: false);
            if (services is null) return new(ServiceReadStatus.Error, Error: "The services key could not be opened.");
            var definition = ReadKey(services, serviceName);
            return definition is null ? new(ServiceReadStatus.NotFound) : new(ServiceReadStatus.Found, definition);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            return new(ServiceReadStatus.AccessDenied, Error: ex.Message);
        }
        catch (IOException ex)
        {
            return new(ServiceReadStatus.Error, Error: ex.Message);
        }
    }

    /// <summary>
    /// Every auto-start Win32 service as a persistence entry. A key that
    /// cannot be read is listed with the reason rather than skipped, so it
    /// never looks like a removal.
    /// </summary>
    public static IReadOnlyList<PersistenceEntry> ReadAutoStartServices(CancellationToken cancellationToken)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
        using var services = root.OpenSubKey(ServicesKey, writable: false) ?? throw new IOException("The services key could not be opened.");
        var entries = new List<PersistenceEntry>();
        foreach (var name in services.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ServiceAnalysis.IsValidServiceName(name)) continue;
            ServiceDefinition? definition;
            try { definition = ReadKey(services, name); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
            {
                entries.Add(new(name, "Unreadable: access denied."));
                continue;
            }
            if (definition is { IsAutoStartWin32Service: true }) entries.Add(new(name, definition.ToProjection()));
        }
        return entries;
    }

    /// <summary>The service's definition, or null when its key does not exist (or vanished while reading).</summary>
    private static ServiceDefinition? ReadKey(RegistryKey services, string name)
    {
        using var key = services.OpenSubKey(name, writable: false);
        if (key is null) return null;
        string? Text(RegistryKey k, string value) => k.GetValue(value, null, RegistryValueOptions.DoNotExpandEnvironmentNames) switch
        {
            string text => text,
            string[] lines => string.Join(" ", lines),
            _ => null,
        };
        var type = key.GetValue("Type") is int t ? t : 0;
        var start = key.GetValue("Start") is int s ? s : -1;
        string? dll;
        using (var parameters = key.OpenSubKey("Parameters", writable: false))
            dll = parameters is null ? null : Text(parameters, "ServiceDll");
        dll ??= Text(key, "ServiceDll");
        return new ServiceDefinition(type, start, Text(key, "ImagePath"), dll, Text(key, "ObjectName"), Text(key, "FailureCommand"));
    }
}
