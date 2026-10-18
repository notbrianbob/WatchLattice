using System.Runtime.Versioning;
using System.Security;
using System.Text.Json;
using Microsoft.Win32;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>Reads extension install policies and registrations. Abstracted so the watchdog is testable without Windows.</summary>
public interface IExtensionPolicyReader
{
    /// <summary>
    /// The entries for <paramref name="browsers"/> on this computer and for the
    /// given users, and the scopes that were actually read (a user whose
    /// registry hive is not loaded is not read, which is not a change).
    /// </summary>
    (IReadOnlyList<PolicyEntry> Entries, IReadOnlyList<string> Scopes) Read(
        IReadOnlyList<string> browsers, IReadOnlyList<(string Sid, string Name)> users, CancellationToken cancellationToken);
}

/// <summary>
/// Reads, from the machine and from each signed-in user's registry hive:
/// the browsers' <c>ExtensionInstallForcelist</c> and <c>ExtensionSettings</c>
/// policies (and Firefox's <c>Extensions\Install</c>), and the
/// external-extension registrations other programs use to install an
/// extension into every profile (<c>Software\Google\Chrome\Extensions</c> and
/// the Edge and Firefox equivalents). Strictly read-only.
/// </summary>
public sealed class WindowsExtensionPolicyReader : IExtensionPolicyReader
{
    public const string ForceInstallKind = "force-install (ExtensionInstallForcelist)";
    public const string SettingsForceKind = "force-install (ExtensionSettings)";
    public const string SettingsNormalKind = "install (ExtensionSettings)";
    public const string FirefoxInstallKind = @"install (Extensions\Install)";
    public const string ExternalKind = "external install registration";

    private const int MaxValueLength = 1024 * 1024;

    private static string PolicyKey(string browser) => browser switch
    {
        Browsers.Edge => @"Software\Policies\Microsoft\Edge",
        Browsers.Chrome => @"Software\Policies\Google\Chrome",
        _ => @"Software\Policies\Mozilla\Firefox",
    };

    private static string[] ExternalKeys(string browser) => browser switch
    {
        Browsers.Edge => new[] { @"Software\Microsoft\Edge\Extensions", @"Software\Wow6432Node\Microsoft\Edge\Extensions" },
        Browsers.Chrome => new[] { @"Software\Google\Chrome\Extensions", @"Software\Wow6432Node\Google\Chrome\Extensions" },
        _ => new[] { @"Software\Mozilla\Firefox\Extensions", @"Software\Wow6432Node\Mozilla\Firefox\Extensions" },
    };

    public (IReadOnlyList<PolicyEntry> Entries, IReadOnlyList<string> Scopes) Read(
        IReadOnlyList<string> browsers, IReadOnlyList<(string Sid, string Name)> users, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Extension policies are only available on Windows.");
        }

        var entries = new List<PolicyEntry>();
        var scopes = new List<string>();

        using (var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        {
            entries.AddRange(ReadScope(machine, "", "Machine", "this computer (all users)", browsers));
            scopes.Add("Machine");
        }

        using var hives = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
        var loaded = new HashSet<string>(hives.GetSubKeyNames(), StringComparer.OrdinalIgnoreCase);
        foreach (var (sid, name) in users.Where(u => loaded.Contains(u.Sid)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                entries.AddRange(ReadScope(hives, sid + @"\", "User:" + sid, "user " + name, browsers));
                scopes.Add("User:" + sid);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
            {
                // Another user's hive without administrator rights: not read, so not compared.
            }
        }
        return (entries, scopes);
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<PolicyEntry> ReadScope(RegistryKey root, string prefix, string scope, string scopeName, IReadOnlyList<string> browsers)
    {
        var entries = new List<PolicyEntry>();
        foreach (var browser in browsers)
        {
            using (var policy = root.OpenSubKey(prefix + PolicyKey(browser), writable: false))
            {
                if (policy is not null)
                {
                    if (browser == Browsers.Firefox)
                    {
                        using var install = policy.OpenSubKey(@"Extensions\Install", writable: false);
                        foreach (var url in Strings(install))
                        {
                            entries.Add(new PolicyEntry(browser, scope, scopeName, FirefoxInstallKind, url));
                        }
                    }
                    else
                    {
                        using var forcelist = policy.OpenSubKey("ExtensionInstallForcelist", writable: false);
                        foreach (var item in Strings(forcelist).Select(ParseForcelistValue).OfType<(string Id, string? UpdateUrl)>())
                        {
                            entries.Add(new PolicyEntry(browser, scope, scopeName, ForceInstallKind, item.Id, item.UpdateUrl));
                        }
                    }

                    if (Text(policy.GetValue("ExtensionSettings")) is { } json)
                    {
                        entries.AddRange(ParseExtensionSettings(json, browser, scope, scopeName));
                    }
                }
            }

            foreach (var keyPath in ExternalKeys(browser))
            {
                using var external = root.OpenSubKey(prefix + keyPath, writable: false);
                if (external is null)
                {
                    continue;
                }
                if (browser == Browsers.Firefox)
                {
                    // Firefox: one value per add-on ID, holding the folder or file it loads from.
                    foreach (var name in external.GetValueNames().Where(n => n.Length > 0))
                    {
                        entries.Add(new PolicyEntry(browser, scope, scopeName, ExternalKind, name, Text(external.GetValue(name))));
                    }
                }
                else
                {
                    // Chromium: one subkey per extension ID, with update_url or path.
                    foreach (var id in external.GetSubKeyNames())
                    {
                        using var item = external.OpenSubKey(id, writable: false);
                        var location = Text(item?.GetValue("update_url")) ?? Text(item?.GetValue("path"));
                        entries.Add(new PolicyEntry(browser, scope, scopeName, ExternalKind, id, location));
                    }
                }
            }
        }
        return entries.DistinctBy(e => e.Key);
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<string> Strings(RegistryKey? key) =>
        key is null
            ? Array.Empty<string>()
            : key.GetValueNames().Select(n => Text(key.GetValue(n))).OfType<string>().Where(v => v.Length > 0);

    private static string? Text(object? value)
    {
        var text = value switch
        {
            string s => s,
            string[] lines => string.Join("\n", lines),
            _ => null,
        };
        return text is null ? null : text.Length > MaxValueLength ? text[..MaxValueLength] : text.Trim();
    }

    /// <summary>A forcelist value: <c>id</c> or <c>id;update URL</c>.</summary>
    public static (string Id, string? UpdateUrl)? ParseForcelistValue(string value)
    {
        var parts = value.Split(';', 2, StringSplitOptions.TrimEntries);
        return parts[0].Length == 0 ? null : (parts[0], parts.Length > 1 && parts[1].Length > 0 ? parts[1] : null);
    }

    /// <summary>
    /// The entries of an <c>ExtensionSettings</c> policy (JSON keyed by
    /// extension ID) that install an extension: <c>force_installed</c> or
    /// <c>normal_installed</c>. Defaults (<c>*</c>) and update-URL rules
    /// install nothing on their own and are left out. Invalid JSON yields one
    /// entry saying so, so that a broken policy is still visible.
    /// </summary>
    public static IReadOnlyList<PolicyEntry> ParseExtensionSettings(string json, string browser, string scope, string scopeName)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return Array.Empty<PolicyEntry>();
            }
            var entries = new List<PolicyEntry>();
            foreach (var item in document.RootElement.EnumerateObject())
            {
                var mode = item.Value.GetStringOrNull("installation_mode");
                var kind = mode switch
                {
                    "force_installed" => SettingsForceKind,
                    "normal_installed" => SettingsNormalKind,
                    _ => null,
                };
                if (kind is null || item.Name == "*" || item.Name.StartsWith("update_url:", StringComparison.Ordinal))
                {
                    continue;
                }
                var location = item.Value.GetStringOrNull("update_url") ?? item.Value.GetStringOrNull("install_url");
                foreach (var id in item.Name.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    entries.Add(new PolicyEntry(browser, scope, scopeName, kind, id, location));
                }
            }
            return entries;
        }
        catch (JsonException)
        {
            return new[] { new PolicyEntry(browser, scope, scopeName, "ExtensionSettings (not valid JSON)", "(unparsed)") };
        }
    }
}
