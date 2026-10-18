using System.Security;

namespace WatchLattice.ScriptHostAudit.Tests;

/// <summary>Security log 4688 events shaped the way EventRecord.ToXml() renders them, and a log that serves them.</summary>
internal static class Events
{
    public const string PowerShell = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    public const string Word = @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    public const string Explorer = @"C:\Windows\explorer.exe";
    public const string VsCode = @"C:\Users\alex\AppData\Local\Programs\Microsoft VS Code\Code.exe";

    /// <summary>A version 2 event (Windows 10 and later), with every field Windows writes.</summary>
    public static string Xml(long recordId, string newProcess, string? commandLine = "", string? parent = Explorer,
        int eventId = 4688, int version = 2, string user = "alex", string elevation = "%%1938", string label = "S-1-16-8192",
        string targetUser = "-", string targetSid = "S-1-0-0")
    {
        static string E(string? value) => SecurityElement.Escape(value ?? "") ?? "";
        var data = new List<(string, string?)>
        {
            ("SubjectUserSid", "S-1-5-21-1111111111-2222222222-3333333333-1001"),
            ("SubjectUserName", user),
            ("SubjectDomainName", "DESKTOP-TEST"),
            ("SubjectLogonId", "0x5a3c1"),
            ("NewProcessId", "0x1a2c"),
            ("NewProcessName", newProcess),
            ("TokenElevationType", elevation),
            ("ProcessId", "0x2b4"),
            ("CommandLine", commandLine),
        };
        if (version >= 2)
        {
            data.Add(("TargetUserSid", targetSid));
            data.Add(("TargetUserName", targetUser));
            data.Add(("TargetDomainName", targetUser == "-" ? "-" : "DESKTOP-TEST"));
            data.Add(("TargetLogonId", "0x0"));
            data.Add(("ParentProcessName", parent));
            data.Add(("MandatoryLabel", label));
        }
        var fields = string.Concat(data.Select(d => $"<Data Name='{d.Item1}'>{E(d.Item2)}</Data>"));
        return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            + "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>"
            + $"<EventID>{eventId}</EventID><Version>{version}</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode>"
            + "<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-10-18T06:00:00.1234567Z'/>"
            + $"<EventRecordID>{recordId}</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8'/>"
            + "<Channel>Security</Channel><Computer>DESKTOP-TEST</Computer><Security/></System>"
            + $"<EventData>{fields}</EventData></Event>";
    }

    /// <summary>A parsed event. An empty command line means just the quoted program; null means Windows didn't record one.</summary>
    public static ProcessCreationEvent Launch(long recordId, string newProcess, string? commandLine = "", string? parent = Explorer) =>
        ProcessCreationEvent.FromXml(Xml(recordId, newProcess, commandLine == "" ? $"\"{newProcess}\"" : commandLine, parent))
        ?? throw new InvalidOperationException("Fixture event did not parse.");
}

/// <summary>
/// A Security log in memory. Record IDs are positions in the log; process
/// creation events sit among other records, the way they do in a real log.
/// </summary>
internal sealed class FakeLog : IProcessCreationSource
{
    private readonly List<(long Id, ProcessCreationEvent? Launch)> _records = new();

    public AuditStatus Status { get; set; } = new(true, true);

    public Exception? ReadError { get; set; }

    public long? Oldest { get; set; }

    public int ReadCalls { get; private set; }

    public long NextId => (_records.Count == 0 ? Oldest ?? 1 : _records[^1].Id + 1);

    /// <summary>Adds records that are not process creation events, such as logons.</summary>
    public FakeLog Other(int count = 1)
    {
        for (var i = 0; i < count; i++) _records.Add((NextId, null));
        return this;
    }

    public FakeLog Add(string newProcess, string? commandLine = "", string? parent = Events.Explorer)
    {
        _records.Add((NextId, Events.Launch(NextId, newProcess, commandLine, parent)));
        return this;
    }

    /// <summary>Empties the log, the way clearing it in Event Viewer does: record IDs start again at 1.</summary>
    public void Clear()
    {
        _records.Clear();
        Oldest = null;
    }

    /// <summary>Drops the oldest records, the way a full log overwrites them.</summary>
    public void Overwrite(int count)
    {
        _records.RemoveRange(0, Math.Min(count, _records.Count));
    }

    public AuditStatus ReadAuditStatus() => Status;

    public LogRange ReadRange()
    {
        if (ReadError is not null) throw ReadError;
        return _records.Count == 0 ? new LogRange(null, null) : new LogRange(_records[0].Id, _records[^1].Id);
    }

    public ProcessCreationBatch ReadAfter(long afterRecordId, Func<string, bool> wanted, int max, CancellationToken cancellationToken)
    {
        if (ReadError is not null) throw ReadError;
        ReadCalls++;
        var events = new List<ProcessCreationEvent>();
        long? newest = null;
        var read = 0;
        var truncated = false;
        foreach (var (id, launch) in Enumerable.Reverse(_records))
        {
            if (launch is null) continue;
            if (id <= afterRecordId) break;
            newest ??= id;
            if (++read > max)
            {
                truncated = true;
                break;
            }
            if (wanted(launch.HostName)) events.Add(launch);
        }
        events.Reverse();
        return new ProcessCreationBatch(events, newest, truncated);
    }
}
