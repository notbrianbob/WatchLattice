using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WatchLattice.Updater;

public enum SignatureStatus
{
    NotSigned,
    Valid,
    Invalid,
}

/// <summary>The Authenticode state of one file; Publisher is the signer certificate's subject when Valid.</summary>
public sealed record FileSignature(SignatureStatus Status, string? Publisher = null, string? Problem = null)
{
    public static FileSignature NotSigned { get; } = new(SignatureStatus.NotSigned);
}

/// <summary>Reads a file's Authenticode signature.</summary>
public interface ISignatureVerifier
{
    FileSignature Verify(string path);
}

/// <summary>
/// Decides whether a staged package may replace an install, based on code
/// signatures. The installed hub executable is the anchor: once an install is
/// signed, every update must be signed too, and our own files by the same
/// publisher, so a release can never quietly drop or change its signature.
/// Installs that were never signed (v0.1.0) accept unsigned packages, which
/// keeps them updatable; a signature that is present must still be valid.
/// </summary>
public static class SignaturePolicy
{
    /// <summary>Executables and DLLs WatchLattice builds itself; everything else in the package is third-party.</summary>
    public static bool IsOwnFile(string fileName) =>
        fileName.StartsWith("WatchLattice.", StringComparison.OrdinalIgnoreCase)
        || fileName.StartsWith("ScanAlways.", StringComparison.OrdinalIgnoreCase);

    public static bool IsSignable(string fileName) =>
        fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Checks every .exe and .dll under the staged folders against the
    /// installed hub executable. Returns null when the package may be
    /// installed, otherwise the reason it may not.
    /// </summary>
    public static string? Check(ISignatureVerifier verifier, string installedHubExecutable,
        IEnumerable<string> stagedDirectories, string stagingRoot, Action<string> log)
    {
        var anchor = File.Exists(installedHubExecutable) ? verifier.Verify(installedHubExecutable) : FileSignature.NotSigned;
        if (anchor.Status == SignatureStatus.Invalid)
        {
            // Refusing here would leave the install stuck on a broken copy
            // forever; report it and fall back to the unsigned-install rules.
            log($"Warning: the installed {Path.GetFileName(installedHubExecutable)} has an invalid signature ({anchor.Problem}).");
            anchor = FileSignature.NotSigned;
        }
        var required = anchor.Status == SignatureStatus.Valid ? anchor.Publisher : null;

        var signedOwnFiles = 0;
        string? releasePublisher = null;
        foreach (var directory in stagedDirectories.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                var name = Path.GetFileName(file);
                if (!IsSignable(name)) continue;
                var relative = Path.GetRelativePath(stagingRoot, file);
                var signature = verifier.Verify(file);
                switch (signature.Status)
                {
                    case SignatureStatus.Invalid:
                        return $"{relative} has an invalid signature: {signature.Problem}";
                    case SignatureStatus.NotSigned when required is not null:
                        return $"{relative} is not signed, but the installed WatchLattice is signed by {required}.";
                    case SignatureStatus.Valid when required is not null && IsOwnFile(name)
                        && !string.Equals(signature.Publisher, required, StringComparison.Ordinal):
                        return $"{relative} is signed by {signature.Publisher}, not by {required} like the installed WatchLattice.";
                    case SignatureStatus.Valid when IsOwnFile(name):
                        signedOwnFiles++;
                        releasePublisher ??= signature.Publisher;
                        break;
                }
            }
        }

        if (required is not null) log($"Code signatures verified: signed by {required}, like the installed copy.");
        else if (signedOwnFiles > 0) log($"The release is code-signed by {releasePublisher}; future updates must keep that signature.");
        else log("The release is not code-signed; the installed copy is not signed either, so the SHA-256 check is what protects this update.");
        return null;
    }
}

/// <summary>Verifies Authenticode signatures with WinVerifyTrust, checking revocation of the whole chain.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAuthenticodeVerifier : ISignatureVerifier
{
    private const uint TrustENoSignature = 0x800B0100;
    private const uint TrustESubjectFormUnknown = 0x800B0003;
    private const uint TrustEProviderUnknown = 0x800B0001;

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public FileSignature Verify(string path)
    {
        var result = WinVerifyTrustFile(path, out var lastError);
        if (result == 0)
        {
            try
            {
                // X509CertificateLoader has no replacement for reading the signer of a
                // signed file, which is what this needs; the file was already verified above.
#pragma warning disable SYSLIB0057
                using var certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
                return new FileSignature(SignatureStatus.Valid, certificate.Subject);
            }
            catch (CryptographicException ex)
            {
                return new FileSignature(SignatureStatus.Invalid, Problem: "could not read the signer certificate: " + ex.Message);
            }
        }

        // WinVerifyTrust reports a damaged signature as "no signature" too;
        // the last error tells them apart.
        if ((uint)result is TrustESubjectFormUnknown or TrustEProviderUnknown
            || (uint)result == TrustENoSignature && (uint)lastError is TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown)
        {
            return FileSignature.NotSigned;
        }
        return new FileSignature(SignatureStatus.Invalid, Problem: $"{new Win32Exception(result).Message} (0x{result:X8})");
    }

    private static int WinVerifyTrustFile(string path, out int lastError)
    {
        var filePath = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = filePath,
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WinTrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                dwUIChoice = 2,            // WTD_UI_NONE
                fdwRevocationChecks = 1,   // WTD_REVOKE_WHOLECHAIN
                dwUnionChoice = 1,         // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 1,         // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x80,        // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            lastError = Marshal.GetLastWin32Error();
            data.dwStateAction = 2;        // WTD_STATEACTION_CLOSE
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(filePath);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
