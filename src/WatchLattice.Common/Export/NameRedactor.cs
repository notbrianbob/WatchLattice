using System.Text.RegularExpressions;

namespace WatchLattice.Common.Export;

/// <summary>
/// Replaces the Windows user name, computer name and e-mail addresses in
/// exported text with placeholders, so an export can be shared without saying
/// whose computer it came from. Names are matched as whole words, ignoring
/// case, so they are caught in paths (C:\Users\name\...), in JSON with escaped
/// backslashes, and in log lines. Names shorter than three characters are left
/// alone: hiding them would mangle ordinary words.
/// </summary>
public sealed class NameRedactor
{
    public const string UserPlaceholder = "<user>";
    public const string ComputerPlaceholder = "<computer>";
    public const string EmailPlaceholder = "<email>";
    private const int MinimumLength = 3;

    private static readonly Regex Email = new(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private readonly List<(Regex Pattern, string Placeholder)> _names = new();
    private readonly bool _enabled;

    /// <summary>Changes nothing.</summary>
    public static NameRedactor None { get; } = new(enabled: false);

    private NameRedactor(bool enabled) => _enabled = enabled;

    /// <param name="userNames">The account's names: user name, and its profile folder's name when that differs.</param>
    /// <param name="computerNames">The computer's names: machine name, and the domain when it differs.</param>
    public NameRedactor(IEnumerable<string?> userNames, IEnumerable<string?> computerNames) : this(enabled: true)
    {
        // Longest first, so "brian.smith" is replaced before "brian".
        foreach (var (name, placeholder) in userNames.Select(n => (n, UserPlaceholder))
                     .Concat(computerNames.Select(n => (n, ComputerPlaceholder)))
                     .Where(p => p.n is { Length: >= MinimumLength })
                     .DistinctBy(p => p.n!.ToUpperInvariant())
                     .OrderByDescending(p => p.n!.Length))
        {
            // Whole word: not touching a letter, digit, '_' or '-' either side, so "Bri" doesn't hit "Bridge".
            var pattern = new Regex(@"(?<![\p{L}\p{N}_-])" + Regex.Escape(name!) + @"(?![\p{L}\p{N}_-])",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            _names.Add((pattern, placeholder));
        }
    }

    /// <summary>The names of the account and computer this runs on.</summary>
    public static NameRedactor ForCurrentUser()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var profileName = string.IsNullOrEmpty(profile) ? null : Path.GetFileName(profile.TrimEnd('\\', '/'));
        return new NameRedactor(new[] { Environment.UserName, profileName },
            new[] { Environment.MachineName, Environment.UserDomainName });
    }

    public string Apply(string text)
    {
        if (!_enabled || string.IsNullOrEmpty(text)) return text;
        try
        {
            text = Email.Replace(text, EmailPlaceholder);
            foreach (var (pattern, placeholder) in _names) text = pattern.Replace(text, placeholder);
            return text;
        }
        catch (RegexMatchTimeoutException)
        {
            // Never let odd text leak a name: say what was there instead of showing it.
            return "(text hidden: it could not be checked for names)";
        }
    }
}
