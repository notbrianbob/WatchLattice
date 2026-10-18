using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace WatchLattice.ScriptHostAudit;

/// <summary>Whether Windows is set to write the events this module reads. Null means it could not be determined.</summary>
/// <param name="ProcessCreationAudited">The "Audit Process Creation" subcategory records successes.</param>
/// <param name="CommandLineIncluded">"Include command line in process creation events" is turned on.</param>
/// <param name="Error">Why the audit policy could not be read, when it could not.</param>
public sealed record AuditStatus(bool? ProcessCreationAudited, bool? CommandLineIncluded, string? Error = null);

/// <summary>The Security log's record ID range. Both null when the log is empty.</summary>
public sealed record LogRange(long? Oldest, long? Newest);

/// <summary>New process creation events, newest last.</summary>
/// <param name="Events">The matching events after the bookmark, oldest first.</param>
/// <param name="NewestRecordId">The newest 4688 record read, matching or not; null when none was newer than the bookmark.</param>
/// <param name="Truncated">More events were newer than the bookmark than could be read; the oldest of them were skipped.</param>
public sealed record ProcessCreationBatch(IReadOnlyList<ProcessCreationEvent> Events, long? NewestRecordId, bool Truncated);

/// <summary>Reads process creation auditing state and events. Read-only: it never changes audit policy or the log.</summary>
public interface IProcessCreationSource
{
    AuditStatus ReadAuditStatus();

    /// <summary>The Security log's oldest and newest record IDs. Throws when the log can't be read.</summary>
    LogRange ReadRange();

    /// <summary>
    /// 4688 events with a record ID above <paramref name="afterRecordId"/>
    /// whose new process file name passes <paramref name="wanted"/>, reading
    /// at most <paramref name="max"/> events. Throws when the log can't be read.
    /// </summary>
    ProcessCreationBatch ReadAfter(long afterRecordId, Func<string, bool> wanted, int max, CancellationToken cancellationToken);
}

/// <summary>
/// The real source: the Security event log through the Windows event log
/// API, the advanced audit policy through <c>AuditQuerySystemPolicy</c>, and
/// the command line setting from its policy registry value. The hub's
/// service account (LocalSystem) can read all three; an ordinary account
/// can read none of them.
/// </summary>
public sealed class WindowsProcessCreationSource : IProcessCreationSource
{
    /// <summary>The "Audit Process Creation" subcategory (Detailed Tracking).</summary>
    public static readonly Guid ProcessCreationSubcategory = new("0cce922b-69ae-11d9-bed3-505054503030");

    public const string CommandLinePolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
    public const string CommandLinePolicyValue = "ProcessCreationIncludeCmdLine_Enabled";

    // EventData order of 4688 (version 1 and 2): NewProcessName is the sixth field.
    private const int NewProcessNameIndex = 5;

    public AuditStatus ReadAuditStatus()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new AuditStatus(null, null, "Process creation auditing is a Windows feature.");
        }
        return ReadWindowsAuditStatus();
    }

    public LogRange ReadRange()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The Security event log is only available on Windows.");
        }
        return ReadWindowsRange();
    }

    public ProcessCreationBatch ReadAfter(long afterRecordId, Func<string, bool> wanted, int max, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The Security event log is only available on Windows.");
        }
        return ReadWindowsAfter(afterRecordId, wanted, max, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private static AuditStatus ReadWindowsAuditStatus()
    {
        bool? commandLine = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CommandLinePolicyKey);
            commandLine = key?.GetValue(CommandLinePolicyValue) is int value && value == 1;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Unknown; the events themselves show whether command lines arrive.
        }

        var subcategory = ProcessCreationSubcategory;
        if (!AuditQuerySystemPolicy(ref subcategory, 1, out var buffer))
        {
            var error = Marshal.GetLastPInvokeError();
            return new AuditStatus(null, commandLine, error switch
            {
                5 or 1314 => "this account may not read the audit policy (run the hub as its service)",
                _ => $"AuditQuerySystemPolicy failed with error {error}",
            });
        }
        try
        {
            var policy = Marshal.PtrToStructure<AuditPolicyInformation>(buffer);
            return new AuditStatus((policy.AuditingInformation & PolicyAuditEventSuccess) != 0, commandLine);
        }
        finally
        {
            AuditFree(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static LogRange ReadWindowsRange()
    {
        using var session = new EventLogSession();
        var info = session.GetLogInformation(ProcessCreationEvent.Channel, PathType.LogName);
        if (info.RecordCount is not > 0 || info.OldestRecordNumber is not { } oldest)
        {
            return new LogRange(null, null);
        }
        return new LogRange(oldest, oldest + info.RecordCount.Value - 1);
    }

    [SupportedOSPlatform("windows")]
    private static ProcessCreationBatch ReadWindowsAfter(long afterRecordId, Func<string, bool> wanted, int max, CancellationToken cancellationToken)
    {
        // Newest first, so reading stops at the bookmark instead of scanning the
        // whole log, and a flood keeps the newest events.
        var query = new EventLogQuery(ProcessCreationEvent.Channel, PathType.LogName, $"*[System[(EventID={ProcessCreationEvent.EventId})]]")
        {
            ReverseDirection = true,
        };
        var events = new List<ProcessCreationEvent>();
        long? newest = null;
        var read = 0;
        var truncated = false;
        using var reader = new EventLogReader(query);
        while (reader.ReadEvent() is { } record)
        {
            using (record)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (record.RecordId is not { } id || id <= afterRecordId) break;
                newest ??= id;
                if (++read > max)
                {
                    truncated = true;
                    break;
                }
                var properties = record.Properties;
                if (properties.Count <= NewProcessNameIndex || properties[NewProcessNameIndex].Value is not string path
                    || !wanted(ProcessCreationEvent.FileName(path)))
                {
                    continue;
                }
                if (ProcessCreationEvent.FromXml(record.ToXml()) is { } parsed)
                {
                    events.Add(parsed);
                }
            }
        }
        events.Reverse();
        return new ProcessCreationBatch(events, newest, truncated);
    }

    private const uint PolicyAuditEventSuccess = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy(ref Guid subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern void AuditFree(IntPtr buffer);
}
