namespace WatchLattice.Common.Alerts;

/// <summary>Where an alert or a group of alerts stands with the signed-in user.</summary>
public enum AlertReviewState { New, Acknowledged, Dismissed }

/// <summary>
/// Repeats of one alert: the same module, code and resource (or title, when
/// an alert names no resource). Display-only; every occurrence stays in the
/// feed and the Event Log.
/// </summary>
public sealed record AlertGroup(string Key, IReadOnlyList<ProtectionAlert> Alerts, AlertReviewState State)
{
    /// <summary>The newest occurrence, which the group's row shows.</summary>
    public ProtectionAlert Latest => Alerts[0];
    public int Count => Alerts.Count;
    public DateTimeOffset FirstSeen => Alerts[^1].At;
    public DateTimeOffset LastSeen => Alerts[0].At;
    public AlertSeverity Severity => Alerts.Max(a => a.Severity);
    /// <summary>Occurrences the user has not acknowledged or dismissed yet.</summary>
    public int NewCount { get; init; }
}

public static class AlertGrouping
{
    public static string KeyFor(ProtectionAlert alert) =>
        string.Join('\u001f', alert.Module, alert.Code, alert.Resource ?? "title:" + alert.Title);

    /// <summary>
    /// Groups repeats, newest group first. With <paramref name="group"/> false
    /// every alert is its own row, but review state still follows its group, so
    /// acknowledging in either view means the same thing.
    /// </summary>
    public static IReadOnlyList<AlertGroup> Build(IEnumerable<ProtectionAlert> alerts, AlertReviewSet review, bool group = true)
    {
        var newestFirst = alerts.OrderByDescending(a => a.At).ThenByDescending(a => a.Id).ToArray();
        IEnumerable<(string Key, ProtectionAlert[] Alerts)> rows = group
            ? newestFirst.GroupBy(KeyFor, StringComparer.Ordinal).Select(g => (g.Key, g.ToArray()))
            : newestFirst.Select(a => (KeyFor(a), new[] { a }));
        return rows.Select(r =>
        {
            var mark = review.Find(r.Key);
            var fresh = r.Alerts.Count(a => mark is null || a.At > mark.ReviewedThrough);
            var state = fresh > 0 || mark is null ? AlertReviewState.New
                : mark.Dismissed ? AlertReviewState.Dismissed : AlertReviewState.Acknowledged;
            return new AlertGroup(r.Key, r.Alerts, state) { NewCount = fresh };
        }).ToArray();
    }
}

/// <summary>The user's review of one group: everything up to <see cref="ReviewedThrough"/> is seen.</summary>
public sealed record AlertReviewMark(string Key, DateTimeOffset ReviewedThrough, bool Dismissed, DateTimeOffset MarkedAt);

/// <summary>An immutable set of review marks, keyed by group.</summary>
public sealed class AlertReviewSet
{
    public const int Limit = 2000;
    public static AlertReviewSet Empty { get; } = new(Array.Empty<AlertReviewMark>());

    private readonly Dictionary<string, AlertReviewMark> _marks;

    public AlertReviewSet(IEnumerable<AlertReviewMark> marks)
    {
        _marks = new(StringComparer.Ordinal);
        foreach (var mark in marks.OrderBy(m => m.MarkedAt)) _marks[mark.Key] = mark;
    }

    public IReadOnlyCollection<AlertReviewMark> Marks => _marks.Values;

    public AlertReviewMark? Find(string key) => _marks.GetValueOrDefault(key);

    /// <summary>
    /// Marks the groups seen through the given time. Acknowledging keeps a
    /// dismissed group hidden only when nothing newer has arrived since.
    /// A later occurrence makes the group new again.
    /// </summary>
    public AlertReviewSet Mark(IEnumerable<(string Key, DateTimeOffset Through)> groups, bool dismiss, DateTimeOffset now)
    {
        var marks = new Dictionary<string, AlertReviewMark>(_marks, StringComparer.Ordinal);
        foreach (var (key, through) in groups)
        {
            var existing = marks.GetValueOrDefault(key);
            var reviewed = existing is null || through > existing.ReviewedThrough ? through : existing.ReviewedThrough;
            var stillDismissed = existing is { Dismissed: true } && through <= existing.ReviewedThrough;
            marks[key] = new(key, reviewed, dismiss || stillDismissed, now);
        }
        return new(Trim(marks.Values));
    }

    /// <summary>Shows dismissed groups again, as acknowledged.</summary>
    public AlertReviewSet Restore(IEnumerable<string> keys, DateTimeOffset now)
    {
        var marks = new Dictionary<string, AlertReviewMark>(_marks, StringComparer.Ordinal);
        foreach (var key in keys)
            if (marks.TryGetValue(key, out var mark) && mark.Dismissed) marks[key] = mark with { Dismissed = false, MarkedAt = now };
        return new(marks.Values);
    }

    private static IEnumerable<AlertReviewMark> Trim(IEnumerable<AlertReviewMark> marks) =>
        marks.OrderByDescending(m => m.MarkedAt).Take(Limit);
}

/// <summary>
/// The signed-in user's acknowledged and dismissed alerts, in their own
/// profile. Only the dashboard reads or writes it; the hub, the feed and the
/// Event Log never see it. Does file I/O; call off the UI thread.
/// </summary>
public sealed class AlertReviewStore
{
    private const int CurrentVersion = 1;
    private readonly object _gate = new();
    private DateTime _stamp = DateTime.MinValue;
    private AlertReviewSet _current = AlertReviewSet.Empty;

    public AlertReviewStore(string? path = null) => FilePath = path ?? DefaultPath;

    /// <summary>In the same per-user folder as the other WatchLattice data.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScanAlways", "alert-review.json");

    public string FilePath { get; }

    /// <summary>Why the review file could not be read or saved, or null.</summary>
    public string? Problem { get; private set; }

    public AlertReviewSet Current
    {
        get { lock (_gate) return _current; }
    }

    /// <summary>Re-reads the file when it changed (another dashboard may have written it). Returns the current set.</summary>
    public AlertReviewSet Refresh()
    {
        lock (_gate)
        {
            try
            {
                var stamp = File.Exists(FilePath) ? File.GetLastWriteTimeUtc(FilePath) : DateTime.MinValue;
                if (stamp != _stamp)
                {
                    _current = stamp == DateTime.MinValue ? AlertReviewSet.Empty : Read(FilePath);
                    _stamp = stamp;
                }
                Problem = null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
            {
                Problem = "Acknowledged alerts could not be read: " + ex.Message;
            }
            return _current;
        }
    }

    /// <summary>Applies a change to the latest file contents and saves it. Throws when it cannot be saved.</summary>
    public AlertReviewSet Update(Func<AlertReviewSet, AlertReviewSet> change)
    {
        lock (_gate)
        {
            Refresh();
            var next = change(_current);
            try
            {
                AtomicJsonFile.Write(FilePath, new ReviewFile(CurrentVersion, next.Marks.ToArray()));
                _stamp = File.GetLastWriteTimeUtc(FilePath);
                Problem = null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                Problem = "Acknowledged alerts could not be saved: " + ex.Message;
                throw;
            }
            _current = next;
            return next;
        }
    }

    private static AlertReviewSet Read(string path)
    {
        var file = AtomicJsonFile.Read<ReviewFile>(path);
        if (file.Version != CurrentVersion || file.Marks is null
            || file.Marks.Any(m => m is null || string.IsNullOrEmpty(m.Key) || m.Key.Length > 2048))
            throw new InvalidDataException("Unsupported or invalid acknowledged-alerts file.");
        return new(file.Marks);
    }

    private sealed record ReviewFile(int Version, AlertReviewMark[] Marks);
}
