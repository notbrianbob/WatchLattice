using System.Text.RegularExpressions;

namespace WatchLattice.ScriptHostAudit;

/// <summary>
/// Hides values that look like passwords, tokens or keys in a command line
/// before it is copied into an alert. The Security log the command line comes
/// from is only readable by administrators, but alerts also reach the tray
/// feed and the Application log, which every user on the PC can read.
/// </summary>
/// <remarks>
/// This catches the common forms (<c>-Password x</c>, <c>/p:x</c>,
/// <c>token=x</c>, <c>https://user:pass@host</c>, <c>Bearer x</c>,
/// <c>ConvertTo-SecureString "x"</c>). It is not a guarantee: a secret passed
/// as a bare positional argument looks like any other word. To keep command
/// lines out of alerts entirely, turn off CommandLineInAlerts. Approvals are
/// matched against the exact command line, so redaction never changes what an
/// approval matches.
/// </remarks>
public static partial class CommandLineRedactor
{
    public const string Mask = "[hidden]";

    private const string Value = """("[^"]*"|'[^']*'|[^\s"';&|,]+)""";

    // -Password value, --token value, -ApiKey "value"
    [GeneratedRegex("""(?<name>(?:^|\s)--?(?:password|passwd|pwd|pass|token|accesstoken|secret|clientsecret|apikey|key|credential|cred|sas)\s+)""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SwitchWithValue();

    // /p:value, /password=value, -pwd:value
    [GeneratedRegex("""(?<name>(?:^|\s)[/-](?:p|pw|pwd|pass|password|token|secret|key|apikey)[:=])""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SwitchWithAttachedValue();

    // password=value, api_key: value, client-secret=value
    [GeneratedRegex("""(?<name>\b(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|api[_-]?key|access[_-]?key|account[_-]?key|sig)\s*[=:]\s*)""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Assignment();

    // https://user:password@host
    [GeneratedRegex("""(?<name>[a-z][a-z0-9+.-]*://[^\s/:@"']+:)[^\s/@"']+(?=@)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlPassword();

    // Authorization: Bearer value, Basic value
    [GeneratedRegex("""(?<name>\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationHeader();

    // ConvertTo-SecureString "value" -AsPlainText
    [GeneratedRegex("""(?<name>ConvertTo-SecureString\s+(?:-String\s+)?)""" + Value, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SecureString();

    /// <summary>The command line with likely secrets replaced by <see cref="Mask"/>, and whether anything was hidden.</summary>
    public static (string Text, bool Hidden) Redact(string commandLine)
    {
        var hidden = false;
        var text = commandLine;
        foreach (var pattern in new[] { SwitchWithValue(), SwitchWithAttachedValue(), Assignment(), UrlPassword(), AuthorizationHeader(), SecureString() })
        {
            text = pattern.Replace(text, m =>
            {
                hidden = true;
                return m.Groups["name"].Value + Mask;
            });
        }
        return (text, hidden);
    }
}
