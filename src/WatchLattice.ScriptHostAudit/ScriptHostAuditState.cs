namespace WatchLattice.ScriptHostAudit;

/// <summary>
/// The auditor's bookmark: the newest Security log record it has read, kept
/// on disk so launches while the hub was stopped are still reported at the
/// next start, and none is reported twice.
/// </summary>
public sealed class ScriptHostAuditState
{
    public const int CurrentVersion = 1;

    public int Version { get; set; } = CurrentVersion;

    /// <summary>Null until the first read, which starts from the newest record without reporting older launches.</summary>
    public long? LastRecordId { get; set; }

    public bool IsValid() => Version == CurrentVersion && LastRecordId is null or >= 0;
}
