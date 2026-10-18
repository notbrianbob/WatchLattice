namespace WatchLattice.Persistence.Verification;

/// <summary>Checks on a target file's evidence, shared by every verifier that resolves a program or DLL.</summary>
public static class FileChecks
{
    public static VerificationCheck TargetCheck(string prefix, string title, ResolvedPath resolved, FileEvidence file)
    {
        var id = prefix + "target";
        if (file.Error is not null && !file.Exists)
            return new(id, title, CheckStatus.Unknown, $"{file.Path} could not be inspected: {file.Error}");
        if (!file.Exists)
            return new(id, title, CheckStatus.Warning,
                $"{file.Path} does not exist. That is inconclusive: the entry may be left over, or waiting for a file to be placed there.");
        if (file.Error is not null)
            return new(id, title, CheckStatus.Unknown, $"{file.Path} exists but could not be read: {file.Error}");
        var facts = $"{file.Path}, {file.Length:N0} bytes, SHA-256 {file.Sha256}" + (file.FileVersion is null ? "" : $", version {file.FileVersion}");
        if (file.IsReparsePoint)
            return new(id, title, CheckStatus.Warning, facts + ". The file is a link (reparse point), so the file that runs may be elsewhere.");
        if (resolved.Kind == PathResolution.SearchOrder && resolved.Note.Contains("relative path", StringComparison.OrdinalIgnoreCase))
            return new(id, title, CheckStatus.Warning, facts + ". " + resolved.Note + " A different folder would run a different file.");
        return new(id, title, CheckStatus.Pass, facts + ".");
    }

    public static VerificationCheck SignatureCheck(string prefix, string label, SignatureEvidence signature)
    {
        var id = prefix + "signature";
        var title = $"Signature {label}";
        var kind = signature.Kind == SignatureKind.Catalog ? "a Windows catalog signature" : "an embedded signature";
        return signature.State switch
        {
            SignatureState.Valid => new(id, title, CheckStatus.Pass,
                $"Valid ({kind}), signed by {CertificateNames.CommonName(signature.Subject) ?? signature.Subject}." +
                (signature.RevocationChecked ? "" : " Certificate revocation could not be checked offline.")),
            SignatureState.NotSigned => new(id, title, CheckStatus.Warning, "The file is not signed, so its publisher cannot be confirmed."),
            SignatureState.Invalid => new(id, title, CheckStatus.Fail,
                $"The signature is not valid: {signature.Problem}. The file may have been modified after it was signed."),
            _ => new(id, title, CheckStatus.Unknown, "The signature could not be checked: " + (signature.Problem ?? "unknown error")),
        };
    }

    public static VerificationCheck PublisherCheck(string prefix, string label, SignatureEvidence signature, string? expected,
        IReadOnlyList<string> familiarPublishers)
    {
        var id = prefix + "publisher";
        var title = $"Publisher {label}";
        var common = CertificateNames.CommonName(signature.Subject);
        var organization = CertificateNames.Organization(signature.Subject);
        if (expected is not null)
            return string.Equals(common, expected, StringComparison.OrdinalIgnoreCase)
                ? new(id, title, CheckStatus.Pass, $"Signed by {common}, the publisher the trusted baseline expects.")
                : new(id, title, CheckStatus.Fail, $"Signed by {common ?? signature.Subject}, but the trusted baseline expects {expected}.");
        var familiar = string.Equals(organization, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
            || familiarPublishers.Any(p => string.Equals(p, common, StringComparison.OrdinalIgnoreCase) || string.Equals(p, organization, StringComparison.OrdinalIgnoreCase));
        return familiar
            ? new(id, title, CheckStatus.Pass, $"Signed by {common} ({organization}), a familiar publisher.")
            : new(id, title, CheckStatus.Warning,
                $"Signed by {common ?? signature.Subject}{(organization is null ? "" : $" ({organization})")}, which is not a familiar publisher. " +
                "Add it to Persistence:FamiliarPublishers if you trust it.");
    }
}
