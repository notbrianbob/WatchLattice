using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Xunit.Sdk;

namespace WatchLattice.Fuzz.Tests.Harness;

/// <summary>
/// Runs a property against many generated inputs. A property is a check that
/// must hold for every input ("never throws", "what was written reads back",
/// "a hidden name never shows"); it fails by throwing.
/// </summary>
/// <remarks>
/// Runs are deterministic: case <c>i</c> of a test always gets the same input
/// for the same seed, so a pull request never fails on input nobody else can
/// get back. The scheduled Fuzz workflow sets <see cref="SeedVariable"/> to a
/// new value each night and raises <see cref="ScaleVariable"/>, which is where
/// new inputs come from. A failure names the seed and prints the input,
/// reduced to the smallest one that still fails. See docs/fuzzing.md.
/// </remarks>
public static class Fuzzer
{
    public const string SeedVariable = "WATCHLATTICE_FUZZ_SEED";
    public const string ScaleVariable = "WATCHLATTICE_FUZZ_SCALE";
    private const int MinimizeBudget = 4000;

    /// <summary>Which set of inputs to run. 0 unless <see cref="SeedVariable"/> says otherwise.</summary>
    public static int Seed { get; } = ReadVariable(SeedVariable, 0, int.MinValue, int.MaxValue);

    /// <summary>Every test runs this many times its usual number of cases.</summary>
    public static int Scale { get; } = ReadVariable(ScaleVariable, 1, 1, 1000);

    /// <summary>Runs <paramref name="check"/> against <paramref name="cases"/> generated inputs (times <see cref="Scale"/>).</summary>
    /// <param name="show">How to print a failing input. Text is printed as a C# string literal by default.</param>
    /// <param name="shrink">Smaller versions of an input to try when it fails, most reduced first.</param>
    public static void Run<T>(int cases, Func<FuzzRandom, T> generate, Action<T> check,
        Func<T, string>? show = null, Func<T, IEnumerable<T>>? shrink = null, [CallerMemberName] string test = "")
    {
        var total = (long)cases * Scale;
        for (long i = 0; i < total; i++)
        {
            var caseSeed = CaseSeed(test, i);
            var input = generate(new FuzzRandom(caseSeed));
            if (Failure(check, input) is not { } failure) continue;

            var steps = 0;
            if (shrink is not null) (input, failure, steps) = Minimize(input, failure, check, shrink);
            throw new FuzzFailureException(
                $"Fuzz case {i} of {total} failed in {test} (seed {Seed}).\n" +
                $"Reproduce: {SeedVariable}={Seed} {ScaleVariable}={Scale} dotnet test tests/WatchLattice.Fuzz.Tests --filter \"FullyQualifiedName~{test}\"\n" +
                $"Failure: {failure.GetType().Name}: {failure.Message}\n" +
                $"Input{(steps > 0 ? " (reduced)" : "")}: {(show ?? Show)(input)}", failure);
        }
    }

    /// <summary>For properties over one piece of text: failing input is reduced and printed as a string literal.</summary>
    public static void RunText(int cases, Func<FuzzRandom, string> generate, Action<string> check, [CallerMemberName] string test = "") =>
        Run(cases, generate, check, Literal, ShrinkText, test);

    /// <summary>For properties over raw bytes: failing input is reduced and printed as hex.</summary>
    public static void RunBytes(int cases, Func<FuzzRandom, byte[]> generate, Action<byte[]> check, [CallerMemberName] string test = "") =>
        Run(cases, generate, check, Hex, ShrinkBytes, test);

    /// <summary>The text as a C# string literal, so a failing input can be pasted into a regression test.</summary>
    public static string Literal(string text)
    {
        var literal = new StringBuilder(text.Length + 2).Append('"');
        foreach (var c in text)
        {
            literal.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\r' => "\\r",
                '\n' => "\\n",
                '\t' => "\\t",
                '\0' => "\\0",
                _ when c < 0x20 || c > 0x7e => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture),
                _ => c.ToString(),
            });
        }
        return literal.Append('"').Append(text.Length > 200 ? $" ({text.Length} characters)" : "").ToString();
    }

    public static string Hex(byte[] bytes) => $"{Convert.ToHexString(bytes)} ({bytes.Length} bytes)";

    /// <summary>Text with a piece cut out: halves first, then ever smaller pieces, then single characters.</summary>
    public static IEnumerable<string> ShrinkText(string text)
    {
        for (var size = text.Length / 2; size >= 1; size /= 2)
        {
            for (var start = 0; start + size <= text.Length; start += size)
            {
                yield return text.Remove(start, size);
            }
        }
        // Then make what is left plainer, so the input shows which character matters.
        for (var i = 0; i < text.Length && i < 64; i++)
        {
            if (text[i] != 'a') yield return string.Concat(text.AsSpan(0, i), "a", text.AsSpan(i + 1));
        }
    }

    public static IEnumerable<byte[]> ShrinkBytes(byte[] bytes)
    {
        for (var size = bytes.Length / 2; size >= 1; size /= 2)
        {
            for (var start = 0; start + size <= bytes.Length; start += size)
            {
                yield return bytes.Take(start).Concat(bytes.Skip(start + size)).ToArray();
            }
        }
        for (var i = 0; i < bytes.Length && i < 64; i++)
        {
            if (bytes[i] != 0)
            {
                var copy = (byte[])bytes.Clone();
                copy[i] = 0;
                yield return copy;
            }
        }
    }

    private static string Show<T>(T input) => input switch
    {
        string text => Literal(text),
        byte[] bytes => Hex(bytes),
        null => "null",
        _ => input.ToString() ?? "",
    };

    private static Exception? Failure<T>(Action<T> check, T input)
    {
        try
        {
            check(input);
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <summary>Keeps taking the first smaller input that fails the same way, until none does or the budget runs out.</summary>
    private static (T Input, Exception Failure, int Steps) Minimize<T>(T input, Exception failure, Action<T> check, Func<T, IEnumerable<T>> shrink)
    {
        var budget = MinimizeBudget;
        var steps = 0;
        var progress = true;
        while (progress && budget > 0)
        {
            progress = false;
            foreach (var smaller in shrink(input))
            {
                if (budget-- <= 0) break;
                if (Failure(check, smaller) is { } same && same.GetType() == failure.GetType())
                {
                    (input, failure, progress) = (smaller, same, true);
                    steps++;
                    break;
                }
            }
        }
        return (input, failure, steps);
    }

    /// <summary>The same on every platform and run, unlike <see cref="string.GetHashCode()"/>.</summary>
    private static int CaseSeed(string test, long index)
    {
        unchecked
        {
            var hash = 2166136261u;
            foreach (var c in test) hash = (hash ^ c) * 16777619u;
            return (int)(hash + (uint)Seed * 2654435761u + (uint)index);
        }
    }

    private static int ReadVariable(string name, int fallback, int min, int max) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? Math.Clamp(value, min, max)
            : fallback;
}

/// <summary>A property failed for a generated input. The message says how to get that input back.</summary>
public sealed class FuzzFailureException : XunitException
{
    public FuzzFailureException(string message, Exception inner) : base(message, inner)
    {
    }
}
