using System.Diagnostics;

namespace WatchLattice.DetectionChecks;

/// <summary>Runs the in-box Windows tools a check uses. Arguments are passed as a list, never through a shell.</summary>
public static class Shell
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    public static Task RunAsync(string file, params string[] arguments) => RunAsync(new[] { 0 }, file, arguments);

    public static async Task RunAsync(int[] okExitCodes, string file, params string[] arguments)
    {
        var start = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {file}.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(Timeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{file} did not finish within {Timeout.TotalSeconds:F0} s.");
        }
        if (!okExitCodes.Contains(process.ExitCode))
        {
            var text = ((await error).Trim() is { Length: > 0 } e ? e : (await output).Trim());
            throw new InvalidOperationException($"{Path.GetFileName(file)} exited with {process.ExitCode}: {text}");
        }
    }

    /// <summary>Runs a script in Windows PowerShell 5.1 (always present) from a temporary file, so no encoded command is involved.</summary>
    public static async Task PowerShellAsync(string script)
    {
        var path = Path.Join(Path.GetTempPath(), $"{Scenarios.Marker}-{Guid.NewGuid():N}.ps1");
        await File.WriteAllTextAsync(path, "$ErrorActionPreference = 'Stop'\r\n" + script, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        try
        {
            await RunAsync("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
