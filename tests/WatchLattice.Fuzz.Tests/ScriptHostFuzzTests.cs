using System.Security;
using System.Text;
using WatchLattice.Common.Alerts;
using WatchLattice.Fuzz.Tests.Harness;
using WatchLattice.ScriptHostAudit;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// Whoever starts a process chooses its command line, and it reaches the hub
/// through the Security log. It must not stop the audit, slow it to a crawl,
/// or carry a secret into an alert that the documented forms should hide.
/// </summary>
public class ScriptHostFuzzTests
{
    private static readonly string[] Words =
    {
        "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "wmic.exe", "winword.exe", "explorer.exe",
        "-enc", "-EncodedCommand", "-e", "-w", "hidden", "-WindowStyle", "/i:", "http://", "https://", "javascript:", "vbscript:",
        "FromBase64String", "iex", "Invoke-Expression", "DownloadString", "scrobj.dll", "url.dll", "-urlcache", "process call create",
        "-Password", "--token", "/p:", "password=", "api_key: ", "Bearer ", "Basic ", "ConvertTo-SecureString", "-String", "://", "user:", "@", "sig=",
        "C:\\Windows\\System32\\", "C:\\Users\\Public\\", "\\", "/", "\"", "'", " ", "|", "*", "?", ";", "&", ",",
    };

    private const string SampleCommandLine =
        "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA -Password Hunter2 https://me:tok@example.test/x?sig=abc";

    private const string SampleEvent =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
        + "<EventID>4688</EventID><Version>2</Version><Level>0</Level><TimeCreated SystemTime='2026-11-20T10:11:12.1234567Z'/><EventRecordID>12345</EventRecordID><Channel>Security</Channel></System>"
        + "<EventData><Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data><Data Name='SubjectUserName'>brian</Data><Data Name='SubjectDomainName'>PC</Data>"
        + "<Data Name='NewProcessId'>0x1a2b</Data><Data Name='NewProcessName'>C:\\Windows\\System32\\mshta.exe</Data><Data Name='TokenElevationType'>%%1938</Data>"
        + "<Data Name='ProcessId'>0x3c4d</Data><Data Name='CommandLine'>mshta.exe https://example.test/a.hta</Data><Data Name='TargetUserSid'>S-1-0-0</Data>"
        + "<Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='ParentProcessName'>C:\\Program Files\\Microsoft Office\\WINWORD.EXE</Data>"
        + "<Data Name='MandatoryLabel'>S-1-16-8192</Data></EventData></Event>";

    /// <summary>The forms docs/threat-model.md says are hidden. {0} is the secret.</summary>
    private static readonly string[] SecretForms =
    {
        "-Password {0}", "-password {0}", "--token {0}", "-ApiKey \"{0}\"", "-Credential '{0}'", "/p:{0}", "/password={0}", "-pwd:{0}", "-key=\"{0}\"",
        "password={0}", "PASSWORD = {0}", "api_key: {0}", "client-secret={0}", "access_token={0}", "sig={0}",
        "https://user:{0}@example.test/path", "ftp://someone:{0}@files.example.test", "Authorization: Bearer {0}", "basic {0}",
        "ConvertTo-SecureString \"{0}\" -AsPlainText", "ConvertTo-SecureString -String '{0}' -Force",
        // A value may be quoted only in part, and a quote left open runs to the end of the line.
        "password=\"\"{0}", "-Password \"abc\"{0}", "token='x'{0}\"y\"", "/p:{0}\"tail\"", "-Password \"{0}", "--token 'abc {0}",
    };

    [Fact]
    public void Redactor_AnyCommandLine_NeverThrows_AndOnlyReportsHidingWhatItChanged()
    {
        Fuzzer.RunText(4000, r => r.Chance(0.4) ? r.Text(Words, 10, 80) : r.Mutate(SampleCommandLine, Words), commandLine =>
        {
            var (text, hidden) = CommandLineRedactor.Redact(commandLine);
            if (!hidden) Assert.Equal(commandLine, text);
            else Assert.Contains(CommandLineRedactor.Mask, text, StringComparison.Ordinal);
            // An alert's text can be redacted again (the full export does) without bringing anything back.
            var again = CommandLineRedactor.Redact(text).Text;
            Assert.True(again.Length <= text.Length, "Redacting twice made the text longer.");
            if (hidden) Assert.Contains(CommandLineRedactor.Mask, again, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void Redactor_SecretInADocumentedForm_NeverReachesTheAlert()
    {
        Fuzzer.Run(4000, r =>
        {
            // Not a word any pattern treats as a switch or keyword, and long enough for a bearer token.
            var secret = "Zq9" + r.Identifier(8, 24);
            var before = string.Join(" ", Enumerable.Range(0, r.Next(4)).Select(_ => r.Pick("powershell.exe", "-NoProfile", "C:\\tools\\deploy.ps1", "-File", "curl", "--verbose", "/c", "x")));
            var after = string.Join(" ", Enumerable.Range(0, r.Next(4)).Select(_ => r.Pick("-Force", "--verbose", "C:\\out.txt", "-ErrorAction Stop", "2", "x")));
            return (Secret: secret, CommandLine: (before + " " + string.Format(r.Pick(SecretForms), secret) + " " + after).Trim());
        }, input =>
        {
            var (text, hidden) = CommandLineRedactor.Redact(input.CommandLine);
            Assert.True(hidden, "Nothing was hidden.");
            Assert.DoesNotContain(input.Secret, text, StringComparison.Ordinal);
        }, input => Fuzzer.Literal(input.CommandLine));
    }

    [Fact]
    public void Redactor_VeryLongCommandLine_IsStillRead()
    {
        // Windows allows 32,767 characters. Each of these once took time that grew with the square
        // of the length; reading them in full (rather than giving up) shows that no longer happens.
        foreach (var commandLine in new[]
        {
            new string('a', 200_000),
            new string('a', 100_000) + "://b:" + new string('c', 100_000),
            "x -key" + new string(' ', 200_000),
            "password" + new string(' ', 200_000) + "x",
            string.Concat(Enumerable.Repeat("a://b:c ", 30_000)),
        })
        {
            var (text, hidden) = CommandLineRedactor.Redact(commandLine);
            Assert.False(hidden);
            Assert.Equal(commandLine, text);
        }
    }

    [Fact]
    public void Classifier_AnyLaunchAndRules_NeverThrows_AndReasonsMatchSeverity()
    {
        Fuzzer.Run(3000, r =>
        {
            var options = new ScriptHostAuditOptions
            {
                AllowedLaunches = Enumerable.Range(0, r.Next(4)).Select(_ => r.Chance(0.6)
                    ? $"{r.Pick("*", "", "winword.exe", "C:\\*\\*.exe", r.Token(Words))}|{r.Pick("*", "powershell.exe", "*\\mshta.exe", r.Token(Words))}|{r.Pick("*", "", "*-File *", "*a*a*a*b", r.Token(Words))}"
                    : r.Text(Words, 4, 12)).ToArray(),
                SuspiciousParents = Enumerable.Range(0, r.Next(3)).Select(_ => r.Token(Words)).ToArray(),
            };
            string Path() => r.Next(4) switch
            {
                0 => r.Token(Words),
                1 => "C:\\Windows\\System32\\" + r.Pick("powershell.exe", "mshta.exe", "rundll32.exe", "certutil.exe", "wmic.exe"),
                2 => "C:\\Users\\Public\\" + r.Pick("powershell.exe", "mshta.exe", "regsvr32.exe"),
                _ => r.Text(Words, 3, 8),
            };
            var launch = new ProcessCreationEvent(r.Next(int.MaxValue), null, Path(),
                r.Chance(0.1) ? null : r.Chance(0.5) ? r.Text(Words, 8, 60) : r.Mutate(SampleCommandLine, Words),
                r.Chance(0.2) ? null : r.Chance(0.5) ? "C:\\Program Files\\Microsoft Office\\" + r.Pick("WINWORD.EXE", "excel.exe", "explorer.exe") : Path(),
                r.Token(), r.Token(), r.Token(), r.Token(), r.Pick("%%1936", "%%1937", "%%1938", r.Token()), r.Pick("S-1-16-8192", "s-1-16-12288", r.Token()));
            return (Options: options, Launch: launch);
        }, input =>
        {
            LaunchClassifier.InvalidRules(input.Options).ToList();
            var assessment = new LaunchClassifier(input.Options).Assess(input.Launch);

            Assert.Equal(assessment.Reasons.Count == 0, assessment.Severity == AlertSeverity.Info);
            if (assessment.Severity == AlertSeverity.Critical) Assert.True(assessment.Reasons.Count >= 2);
            if (assessment.AllowedBy is { } rule) Assert.Contains(rule, input.Options.AllowedLaunches.Select(a => a.Trim()));
            _ = input.Launch.User + input.Launch.Elevation + input.Launch.Integrity + input.Launch.HostName + input.Launch.ParentName;
        }, input => $"{input.Launch}; allowed [{string.Join(", ", input.Options.AllowedLaunches.Select(Fuzzer.Literal))}]; parents [{string.Join(", ", input.Options.SuspiciousParents.Select(Fuzzer.Literal))}]");
    }

    [Fact]
    public void EventXml_AnyText_NeverThrows()
    {
        var words = new[] { "<Data Name='", "'>", "</Data>", "<EventID>", "</EventID>", "<EventRecordID>", "4688", "<!DOCTYPE x [<!ENTITY a 'b'>]>", "&a;", "&#0;", "&lt;", "<![CDATA[", "]]>", "<?xml version='1.0'?>", "xmlns='", "<Data/>", "<x>" };
        Fuzzer.RunText(4000, r => r.Chance(0.2) ? r.Text(words, 10, 60) : r.Mutate(SampleEvent, words), xml =>
        {
            if (ProcessCreationEvent.FromXml(xml) is { } parsed)
            {
                Assert.False(string.IsNullOrWhiteSpace(parsed.NewProcessName));
                Assert.NotNull(parsed.HostName);
                Assert.NotNull(parsed.User);
            }
        });
    }

    [Fact]
    public void EventXml_WrittenAsWindowsWritesIt_ReadsBackExactly()
    {
        Fuzzer.Run(2000, r =>
        {
            // What a field can hold: any printable text, including what XML has to escape.
            string Value() => (r.Identifier() + r.Pick("", " <tag> ", " & ", " \"quoted\" ", " 'single' ", " ]]> ", " \u00e9\u4e2d ") + r.Identifier()).Trim();
            return (Record: (long)r.Next(1, int.MaxValue), Process: "C:\\" + Value() + ".exe", CommandLine: r.Chance(0.2) ? null : Value(),
                Parent: r.Chance(0.2) ? null : "C:\\" + Value(), User: Value(), Domain: Value());
        }, input =>
        {
            string Data(string name, string? value) => $"<Data Name='{name}'>{SecurityElement.Escape(value ?? "-")}</Data>";
            var xml = new StringBuilder("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID>")
                .Append("<TimeCreated SystemTime='2026-11-20T10:11:12.1234567Z'/><EventRecordID>").Append(input.Record).Append("</EventRecordID></System><EventData>")
                .Append(Data("SubjectUserName", input.User)).Append(Data("SubjectDomainName", input.Domain)).Append(Data("NewProcessName", input.Process))
                .Append(Data("CommandLine", input.CommandLine)).Append(Data("TargetUserSid", "S-1-0-0")).Append(Data("TargetUserName", null))
                .Append(Data("ParentProcessName", input.Parent)).Append("</EventData></Event>").ToString();

            var parsed = ProcessCreationEvent.FromXml(xml);

            Assert.NotNull(parsed);
            Assert.Equal(input.Record, parsed.RecordId);
            Assert.Equal(input.Process, parsed.NewProcessName);
            Assert.Equal(input.CommandLine, parsed.CommandLine);
            Assert.Equal(input.Parent, parsed.ParentProcessName);
            Assert.Equal(input.User, parsed.UserName);
            Assert.Equal(input.Domain, parsed.UserDomain);
            Assert.Equal(new DateTimeOffset(2026, 11, 20, 10, 11, 12, TimeSpan.Zero).AddTicks(1234567), parsed.TimeCreated);
        });
    }
}
