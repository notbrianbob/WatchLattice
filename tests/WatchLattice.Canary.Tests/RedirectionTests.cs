using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace WatchLattice.Canary.Tests;

/// <summary>
/// The hub plants canaries as LocalSystem in folders the user owns. A user who
/// swaps a canary folder for a junction, or a canary for a link, must not be
/// able to make it write or delete a file somewhere else (docs/threat-model.md).
/// The "protected" folder here stands in for somewhere like System32.
/// </summary>
public sealed class RedirectionTests
{
    private const string Name = "a.docx";

    [Fact]
    public void Replant_DoesNotWriteThroughAFolderSwappedForALink()
    {
        using var temp = new TempFolder();
        var options = temp.Options(Name);
        new CanaryDeployer(options, NullLogger.Instance).Deploy();
        var target = Protected(temp, "system file");

        Assert.True(SwapFolderForLink(temp.Watched, Path.GetDirectoryName(target)!));
        var second = new CanaryDeployer(options, NullLogger.Instance).Deploy();

        Assert.Empty(second.Active);
        Assert.Equal("system file", File.ReadAllText(target));
    }

    [Fact]
    public void Replant_CreatesNothingInTheFolderALinkPointsTo()
    {
        using var temp = new TempFolder();
        var options = temp.Options(Name);
        new CanaryDeployer(options, NullLogger.Instance).Deploy();
        var elsewhere = Directory.CreateDirectory(Path.Join(temp.Path, "elsewhere")).FullName;

        Assert.True(SwapFolderForLink(temp.Watched, elsewhere));
        new CanaryDeployer(options, NullLogger.Instance).Deploy();

        Assert.Empty(Directory.EnumerateFileSystemEntries(elsewhere));
    }

    [Fact]
    public void Replant_DoesNotWriteThroughACanarySwappedForAFileLink()
    {
        using var temp = new TempFolder();
        var options = temp.Options(Name);
        new CanaryDeployer(options, NullLogger.Instance).Deploy();
        var target = Protected(temp, "system file");
        var canary = Path.Join(temp.Watched, Name);
        File.Delete(canary);
        if (!TryFileLink(canary, target)) return; // Needs Developer Mode or administrator on Windows.

        new CanaryDeployer(options, NullLogger.Instance).Deploy();

        Assert.Equal("system file", File.ReadAllText(target));
    }

    [Fact]
    public void Remove_DoesNotDeleteThroughAFolderSwappedForALink()
    {
        using var temp = new TempFolder();
        var options = temp.Options(Name);
        var deployer = new CanaryDeployer(options, NullLogger.Instance);
        deployer.Deploy();
        // The target even holds an exact copy of the canary, so a hash check alone would pass.
        var target = Protected(temp, "");
        File.Copy(Path.Join(temp.Watched, Name), target, overwrite: true);

        Assert.True(SwapFolderForLink(temp.Watched, Path.GetDirectoryName(target)!));
        deployer.RemoveAll();

        Assert.True(File.Exists(target));
    }

    [Fact]
    public void Remove_StillDeletesAnIntactCanary_AndKeepsAChangedOne()
    {
        using var temp = new TempFolder();
        var options = temp.Options("a.docx", "b.pdf");
        var deployer = new CanaryDeployer(options, NullLogger.Instance);
        deployer.Deploy();
        File.WriteAllText(Path.Join(temp.Watched, "b.pdf"), "encrypted");

        Assert.Equal(1, deployer.RemoveAll());

        Assert.False(File.Exists(Path.Join(temp.Watched, "a.docx")));
        Assert.True(File.Exists(Path.Join(temp.Watched, "b.pdf")));
    }

    [Fact]
    public void Write_RefusesAHardLinkedFile()
    {
        if (!OperatingSystem.IsWindows()) return; // The link-count check is Windows-only; Linux tests cover the path checks.
        using var temp = new TempFolder();
        var target = Protected(temp, "system file");
        var canary = Path.Join(temp.Watched, Name);
        Assert.True(CreateHardLinkW(canary, target, IntPtr.Zero));

        var refusal = RedirectionSafeFile.Write(canary, new byte[] { 1, 2, 3 }, hidden: false);

        Assert.NotNull(refusal);
        Assert.Contains("hard link", refusal!.Reason);
        Assert.Equal("system file", File.ReadAllText(target));
    }

    [Fact]
    public void Write_AcceptsAnOrdinaryFolder_AndAShortNamePath()
    {
        using var temp = new TempFolder();
        var canary = Path.Join(temp.Watched, Name);

        Assert.Null(RedirectionSafeFile.Write(canary, new byte[] { 1, 2, 3 }, hidden: true));
        Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(canary));
        Assert.Null(RedirectionSafeFile.Write(canary, new byte[] { 4 }, hidden: true));
        Assert.Equal(new byte[] { 4 }, File.ReadAllBytes(canary));
        if (OperatingSystem.IsWindows()) Assert.True(File.GetAttributes(canary).HasFlag(FileAttributes.Hidden));
    }

    private static string Protected(TempFolder temp, string content)
    {
        var folder = Directory.CreateDirectory(Path.Join(temp.Path, "protected")).FullName;
        var file = Path.Join(folder, Name);
        File.WriteAllText(file, content);
        return file;
    }

    /// <summary>Replaces the folder with a junction (Windows) or symbolic link to <paramref name="target"/>, as an attacker would.</summary>
    private static bool SwapFolderForLink(string folder, string target)
    {
        foreach (var file in Directory.EnumerateFiles(folder)) File.SetAttributes(file, FileAttributes.Normal);
        Directory.Delete(folder, recursive: true);
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateSymbolicLink(folder, target);
            return true;
        }
        // A junction needs no privilege, which is why a standard user can make one.
        using var mklink = Process.Start(new ProcessStartInfo("cmd.exe") { ArgumentList = { "/c", "mklink", "/J", folder, target }, RedirectStandardOutput = true, UseShellExecute = false })!;
        mklink.WaitForExit();
        return mklink.ExitCode == 0;
    }

    private static bool TryFileLink(string link, string target)
    {
        try
        {
            File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string fileName, string existingFileName, IntPtr securityAttributes);
}
