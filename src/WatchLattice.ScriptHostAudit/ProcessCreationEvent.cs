using System.Globalization;
using System.Xml;

namespace WatchLattice.ScriptHostAudit;

/// <summary>
/// One Security log event 4688, "A new process has been created", as Windows
/// records it. Everything but the record ID and the new process's path is
/// optional: older Windows versions don't record the parent, and the command
/// line is only there when "Include command line in process creation events"
/// is turned on.
/// </summary>
public sealed record ProcessCreationEvent(
    long RecordId,
    DateTimeOffset? TimeCreated,
    string NewProcessName,
    string? CommandLine,
    string? ParentProcessName,
    string? UserName,
    string? UserDomain,
    string? NewProcessId,
    string? ParentProcessId,
    string? TokenElevationType,
    string? MandatoryLabel)
{
    public const int EventId = 4688;
    public const string Channel = "Security";

    private const string EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";

    public string HostName => FileName(NewProcessName);

    public string? ParentName => ParentProcessName is { Length: > 0 } parent ? FileName(parent) : null;

    public string User => (UserDomain, UserName) switch
    {
        ({ Length: > 0 } domain, { Length: > 0 } name) => $"{domain}\\{name}",
        (_, { Length: > 0 } name) => name,
        _ => "(unknown user)",
    };

    /// <summary>"Elevated" or "not elevated" from the token elevation type, or null when Windows didn't say.</summary>
    public string? Elevation => TokenElevationType switch
    {
        "%%1936" => "full token (UAC off or a built-in account)",
        "%%1937" => "elevated",
        "%%1938" => "not elevated",
        _ => null,
    };

    /// <summary>The integrity level's name, from the mandatory label SID.</summary>
    public string? Integrity => MandatoryLabel?.ToUpperInvariant() switch
    {
        "S-1-16-0" => "untrusted",
        "S-1-16-4096" => "low",
        "S-1-16-8192" => "medium",
        "S-1-16-8448" => "medium plus",
        "S-1-16-12288" => "high",
        "S-1-16-16384" => "system",
        "S-1-16-20480" => "protected process",
        _ => null,
    };

    /// <summary>The file name of a Windows path, whatever OS the hub runs on.</summary>
    public static string FileName(string path)
    {
        var trimmed = path.Trim().Trim('"');
        var slash = trimmed.LastIndexOfAny(new[] { '\\', '/' });
        return slash < 0 ? trimmed : trimmed[(slash + 1)..];
    }

    /// <summary>
    /// Reads an event as <c>EventRecord.ToXml()</c> renders it. Returns null
    /// for anything that is not a 4688 event with a record ID and new process
    /// name, rather than throwing.
    /// </summary>
    public static ProcessCreationEvent? FromXml(string xml)
    {
        long? recordId = null;
        int? eventId = null;
        DateTimeOffset? time = null;
        var data = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
                MaxCharactersInDocument = 1024 * 1024,
            };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            // ReadElementContentAsString leaves the reader on the next node, so only
            // move on by hand when nothing was consumed.
            var advance = true;
            while (!advance || reader.Read())
            {
                advance = true;
                if (reader.NodeType != XmlNodeType.Element || reader.NamespaceURI != EventNamespace) continue;
                advance = !(reader.LocalName is "EventID" or "EventRecordID" || (reader.LocalName == "Data" && !reader.IsEmptyElement));
                switch (reader.LocalName)
                {
                    case "EventID":
                        eventId = int.TryParse(reader.ReadElementContentAsString(), NumberStyles.None, CultureInfo.InvariantCulture, out var id) ? id : null;
                        break;
                    case "EventRecordID":
                        recordId = long.TryParse(reader.ReadElementContentAsString(), NumberStyles.None, CultureInfo.InvariantCulture, out var record) ? record : null;
                        break;
                    case "TimeCreated":
                        time = DateTimeOffset.TryParse(reader.GetAttribute("SystemTime"), CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var at) ? at : null;
                        break;
                    case "Data":
                        var name = reader.GetAttribute("Name");
                        var value = reader.IsEmptyElement ? "" : reader.ReadElementContentAsString();
                        if (name is not null) data[name] = value;
                        break;
                }
            }
        }
        catch (XmlException)
        {
            return null;
        }

        if (eventId != EventId || recordId is null || !data.TryGetValue("NewProcessName", out var newProcess) || newProcess.Trim().Length == 0)
        {
            return null;
        }
        // The new process runs as the target account when Windows records one
        // (for example after runas); otherwise as its creator.
        var target = Value(data, "TargetUserName") is not null && Value(data, "TargetUserSid") is not (null or "S-1-0-0");
        return new ProcessCreationEvent(recordId.Value, time, newProcess.Trim(),
            Value(data, "CommandLine"), Value(data, "ParentProcessName"),
            Value(data, target ? "TargetUserName" : "SubjectUserName"), Value(data, target ? "TargetDomainName" : "SubjectDomainName"),
            Value(data, "NewProcessId"), Value(data, "ProcessId"),
            Value(data, "TokenElevationType"), Value(data, "MandatoryLabel"));
    }

    // Windows writes "-" for an empty field.
    private static string? Value(Dictionary<string, string> data, string name) =>
        data.TryGetValue(name, out var value) && value.Trim() is { Length: > 0 } trimmed && trimmed != "-" ? trimmed : null;
}
