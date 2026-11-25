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
/// as a bare positional argument looks like any other word, and a value that
/// starts unquoted and continues in quotes (<c>abc"def"</c>) keeps its quoted part. To keep command
/// lines out of alerts entirely, turn off CommandLineInAlerts. Approvals are
/// matched against the exact command line, so redaction never changes what an
/// approval matches.
/// <para>
/// Whoever starts a process chooses its command line, up to 32,767 characters,
/// so every pattern here has to take time in proportion to the length. Each
/// also has a time limit; a command line that reaches it is hidden whole
/// rather than shown unchecked.
/// </para>
/// </remarks>
public static partial class CommandLineRedactor
{
    public const string Mask = "[hidden]";

    /// <summary>What an alert shows in place of a command line that could not be checked in time.</summary>
    public const string Unchecked = "[hidden: this command line could not be checked for passwords or tokens]";

    private const int TimeoutMilliseconds = 1000;

    // A value that opens with a quote runs on through any quoted and bare pieces that follow it, because
    // "abc"def is one word to the program that receives it; a quote that is never closed takes the rest of
    // the line, as it does for that program. A value that starts bare ends at the next quote, which is
    // usually the end of a quoted URL around it ("https://host/x?sig=abc").
    private const string Value =
        """((?:"[^"]*"|'[^']*')(?:"[^"]*"|'[^']*'|[^\s"';&|,])*(?:"[^"]*|'[^']*)?|"[^"]*|'[^']*|[^\s"';&|,]+)""";

    // -Password value, --token value, -ApiKey "value"
    [GeneratedRegex("""(?<name>(?:^|\s)--?(?:password|passwd|pwd|pass|token|accesstoken|secret|clientsecret|apikey|key|credential|cred|sas)\s+)""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex SwitchWithValue();

    // /p:value, /password=value, -pwd:value
    [GeneratedRegex("""(?<name>(?:^|\s)[/-](?:p|pw|pwd|pass|password|token|secret|key|apikey)[:=])""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex SwitchWithAttachedValue();

    // password=value, api_key: value, client-secret=value
    [GeneratedRegex("""(?<name>\b(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|api[_-]?key|access[_-]?key|account[_-]?key|sig)\s*[=:]\s*)""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex Assignment();

    // https://user:password@host. The scheme's length is capped: an open-ended one made a long run
    // of letters take time that grew with the square of its length. A longer run still matches, from
    // its last 32 characters, and everything before the match is kept either way.
    [GeneratedRegex("""(?<name>[a-z][a-z0-9+.-]{0,31}://[^\s/:@"']+:)[^\s/@"']+(?=@)""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex UrlPassword();

    // Authorization: Bearer value, Basic value
    [GeneratedRegex("""(?<name>\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex AuthorizationHeader();

    // ConvertTo-SecureString "value" -AsPlainText
    [GeneratedRegex("""(?<name>ConvertTo-SecureString\s+(?:-String\s+)?)""" + Value,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeoutMilliseconds)]
    private static partial Regex SecureString();

    /// <summary>The command line with likely secrets replaced by <see cref="Mask"/>, and whether anything was hidden.</summary>
    public static (string Text, bool Hidden) Redact(string commandLine)
    {
        var hidden = false;
        var text = commandLine;
        try
        {
            foreach (var pattern in new[] { SwitchWithValue(), SwitchWithAttachedValue(), Assignment(), UrlPassword(), AuthorizationHeader(), SecureString() })
            {
                text = pattern.Replace(text, m =>
                {
                    hidden = true;
                    return m.Groups["name"].Value + Mask;
                });
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return (Unchecked, true);
        }
        return (text, hidden);
    }
}
