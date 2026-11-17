using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WatchLattice.Canary;

/// <summary>
/// Writes and deletes files in folders a standard user controls, from a hub
/// that runs as LocalSystem, without being redirected somewhere else.
/// </summary>
/// <remarks>
/// Canary folders belong to the signed-in user, who can replace any of them
/// with a junction, or point a name at another file with a symbolic or hard
/// link. A plain File.WriteAllBytes or File.Delete made as LocalSystem would
/// follow that link and overwrite or delete a protected file: a local
/// privilege escalation. So every operation here works on a handle and checks
/// that handle before using it:
/// <list type="bullet">
/// <item>its final path, with every junction and link resolved, is exactly the
/// path that was asked for;</item>
/// <item>it is a file, not a folder, and has only one name (no hard link);</item>
/// <item>nobody else can open the file while the handle is held.</item>
/// </list>
/// A file this code created in the wrong place is deleted through the same
/// handle before anything is written to it. See docs/threat-model.md.
/// </remarks>
public static class RedirectionSafeFile
{
    /// <summary>Why an operation was refused, for the log. Null when it went ahead.</summary>
    public sealed record Refusal(string Reason);

    /// <summary>
    /// Creates or replaces the file at <paramref name="path"/> with
    /// <paramref name="content"/>. Returns null on success, or why it refused.
    /// IO and access errors are thrown as usual.
    /// </summary>
    public static Refusal? Write(string path, byte[] content, bool hidden)
    {
        path = Path.GetFullPath(path);
        if (CheckFolder(path) is { } refusal) return refusal;

        // A read-only or hidden file can't be opened for writing; clear its
        // attributes through a checked handle first.
        if (OperatingSystem.IsWindows() && File.Exists(path))
        {
            using var attributes = Open(path, Access.Attributes, create: false, out _);
            if (Check(attributes, path) is { } problem) return problem;
            File.SetAttributes(attributes, FileAttributes.Normal);
        }

        using var handle = Open(path, Access.ReadWrite, create: true, out var created);
        if (Check(handle, path) is { } refused)
        {
            if (created) DeleteThrough(handle, path);
            return refused;
        }
        RandomAccess.SetLength(handle, 0);
        RandomAccess.Write(handle, content, 0);
        if (hidden && OperatingSystem.IsWindows())
        {
            try
            {
                File.SetAttributes(handle, File.GetAttributes(handle) | FileAttributes.Hidden);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                // Cosmetic only.
            }
        }
        return null;
    }

    /// <summary>
    /// Deletes the file at <paramref name="path"/>, but only if
    /// <paramref name="stillOurs"/> says its current content is the one we
    /// planted. The content is read and the file deleted through one handle,
    /// so it can't be swapped in between. Returns null when deleted.
    /// </summary>
    public static Refusal? DeleteIf(string path, Func<byte[], bool> stillOurs, int maxBytes)
    {
        path = Path.GetFullPath(path);
        if (CheckFolder(path) is { } refusal) return refusal;
        using var handle = Open(path, Access.ReadDelete, create: false, out _);
        if (Check(handle, path) is { } problem) return problem;
        var length = RandomAccess.GetLength(handle);
        if (length > maxBytes) return new("the file is larger than any canary");
        var content = new byte[length];
        var read = 0;
        while (read < content.Length)
        {
            var n = RandomAccess.Read(handle, content.AsSpan(read), read);
            if (n == 0) break;
            read += n;
        }
        if (read != content.Length || !stillOurs(content)) return new("the file is no longer the canary that was planted");
        if (OperatingSystem.IsWindows()) File.SetAttributes(handle, FileAttributes.Normal);
        DeleteThrough(handle, path);
        return null;
    }

    /// <summary>
    /// The folder the file goes in must resolve to itself. This refuses a
    /// junctioned folder before anything is created; the handle check after
    /// opening catches one swapped in afterwards.
    /// </summary>
    private static Refusal? CheckFolder(string path)
    {
        var folder = Path.GetDirectoryName(path);
        if (folder is null) return new("the path has no folder");
        if (!Directory.Exists(folder)) throw new DirectoryNotFoundException($"{folder} does not exist.");
        // Elsewhere only the handle check runs (Linux can't open a folder as a file handle).
        if (!OperatingSystem.IsWindows()) return null;
        using var handle = OpenFolder(folder);
        var actual = FinalPath(handle, folder);
        return Same(actual, LongName(folder)) ? null
            : new($"{folder} leads to {actual} (a junction or link), so nothing was written there");
    }

    private static Refusal? Check(SafeFileHandle handle, string path)
    {
        var actual = FinalPath(handle, path);
        if (!Same(actual, Expected(path))) return new($"{path} leads to {actual} (a junction or link), so it was left alone");
        if (OperatingSystem.IsWindows())
        {
            if (!Native.GetFileInformationByHandle(handle, out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.FileAttributes & (uint)FileAttributes.Directory) != 0) return new($"{path} is a folder");
            if (info.NumberOfLinks != 1) return new($"{path} has {info.NumberOfLinks} names (a hard link), so it was left alone");
        }
        return null;
    }

    private static bool Same(string a, string b) =>
        string.Equals(a.TrimEnd(Path.DirectorySeparatorChar), b.TrimEnd(Path.DirectorySeparatorChar),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    /// <summary>The path as the file system names it: long names instead of 8.3 short ones, but junctions left as they are.</summary>
    private static string Expected(string path)
    {
        if (!OperatingSystem.IsWindows()) return Path.GetFullPath(path);
        var folder = Path.GetDirectoryName(path);
        var name = Path.GetFileName(path);
        if (folder is null || name.Length == 0) return LongName(path);
        return Path.Join(LongName(folder), name);
    }

    private enum Access { Attributes, ReadWrite, ReadDelete }

    private static SafeFileHandle Open(string path, Access access, bool create, out bool created)
    {
        created = false;
        if (OperatingSystem.IsWindows()) return OpenWindows(path, access, create, out created);

        // Elsewhere (the test runs on Linux), the same flow with the portable API.
        if (create && !File.Exists(path))
        {
            try
            {
                created = true;
                return File.OpenHandle(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (File.Exists(path))
            {
                created = false;
            }
        }
        return File.OpenHandle(path, FileMode.Open, access == Access.ReadWrite ? FileAccess.ReadWrite : FileAccess.Read, FileShare.None);
    }

    [SupportedOSPlatform("windows")]
    private static SafeFileHandle OpenWindows(string path, Access access, bool create, out bool created)
    {
        const uint ReadAttributes = 0x80, WriteAttributes = 0x100, Delete = 0x10000, Synchronize = 0x100000;
        const uint GenericRead = 0x80000000, GenericWrite = 0x40000000;
        const uint OpenExisting = 3, OpenAlways = 4, AlreadyExists = 183;
        var desired = access switch
        {
            Access.Attributes => ReadAttributes | WriteAttributes | Synchronize,
            Access.ReadWrite => GenericRead | GenericWrite | Delete,
            _ => GenericRead | WriteAttributes | Delete,
        };
        // No sharing: nothing else can open the file while we check and use it.
        var handle = Native.CreateFileW(Win32Path(path), desired, 0, IntPtr.Zero, create ? OpenAlways : OpenExisting,
            (uint)FileAttributes.Normal, IntPtr.Zero);
        var error = Marshal.GetLastWin32Error();
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw error switch
            {
                2 or 3 => new FileNotFoundException($"{path} does not exist.", path),
                5 => new UnauthorizedAccessException($"Access to {path} is denied."),
                _ => new IOException($"Could not open {path}: {new Win32Exception(error).Message}", error),
            };
        }
        created = create && error != AlreadyExists;
        return handle;
    }

    [SupportedOSPlatform("windows")]
    private static SafeFileHandle OpenFolder(string folder)
    {
        const uint ReadAttributes = 0x80, ShareAll = 7, OpenExisting = 3, BackupSemantics = 0x02000000;
        var handle = Native.CreateFileW(Win32Path(folder), ReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException($"Could not open {folder}: {new Win32Exception(error).Message}", error);
        }
        return handle;
    }

    /// <summary>Where the handle really is, with every junction and link resolved.</summary>
    private static string FinalPath(SafeFileHandle handle, string requested)
    {
        if (!OperatingSystem.IsWindows())
        {
            // Linux keeps the open file's real path under /proc.
            var fd = handle.DangerousGetHandle().ToInt64();
            return new FileInfo($"/proc/self/fd/{fd}").LinkTarget ?? requested;
        }
        var buffer = new StringBuilder(1024);
        var length = Native.GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length > buffer.Capacity)
        {
            buffer = new StringBuilder((int)length);
            length = Native.GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        }
        if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        var final = buffer.ToString();
        if (final.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + final[8..];
        return final.StartsWith(@"\\?\", StringComparison.Ordinal) ? final[4..] : final;
    }

    [SupportedOSPlatform("windows")]
    private static string LongName(string path)
    {
        var full = Path.GetFullPath(path);
        var buffer = new StringBuilder(1024);
        var length = Native.GetLongPathNameW(Win32Path(full), buffer, (uint)buffer.Capacity);
        if (length > buffer.Capacity)
        {
            buffer = new StringBuilder((int)length);
            length = Native.GetLongPathNameW(Win32Path(full), buffer, (uint)buffer.Capacity);
        }
        if (length == 0) return full;
        var result = buffer.ToString();
        if (result.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + result[8..];
        return result.StartsWith(@"\\?\", StringComparison.Ordinal) ? result[4..] : result;
    }

    /// <summary>The extended-length form, so long paths work and nothing is reinterpreted.</summary>
    private static string Win32Path(string full) =>
        full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;

    private static void DeleteThrough(SafeFileHandle handle, string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.Delete(FinalPath(handle, path));
            return;
        }
        const int FileDispositionInfo = 4;
        var delete = 1;
        if (!Native.SetFileInformationByHandle(handle, FileDispositionInfo, ref delete, sizeof(int)))
            throw new IOException($"Could not delete {path}: {new Win32Exception(Marshal.GetLastWin32Error()).Message}");
    }

    [SupportedOSPlatform("windows")]
    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct ByHandleFileInformation
        {
            // FILETIMEs are pairs of 32-bit halves, so they are not 8-byte aligned.
            public uint FileAttributes;
            public uint CreationLow, CreationHigh, LastAccessLow, LastAccessHigh, LastWriteLow, LastWriteHigh;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetLongPathNameW(string shortPath, StringBuilder longPath, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass, ref int information, int size);
    }
}
