using System.Text;
using FsCheck;
using FsCheck.Fluent;

namespace WatchLattice.Fuzz.Tests.Harness;

/// <summary>
/// Inputs from FsCheck, a property-based testing library, as a second source
/// beside <see cref="FuzzRandom"/>. The two are written apart and choose
/// inputs differently: FsCheck grows its inputs from small to large and
/// knows nothing about the formats, where <see cref="FuzzRandom"/> starts
/// from real samples and each format's own words. FsCheck also reduces a
/// failing input itself.
/// </summary>
public static class Arbitrary
{
    /// <summary>Punctuation that means something to at least one of the formats read here.</summary>
    private static readonly string[] Punctuation =
    {
        "{", "}", "[", "]", ":", ",", "\"", "\\", "/", "<", ">", "</", "/>", "=", "&", ";", "#", "%", "|", "*", "?", ".", "..", "-", "+", "@", "'", "`",
        " ", "\t", "\n", "\r\n", "\0", "null", "true", "0", "1", "-1", "\\u", "\\ud800", "\ud800", "\udc00", "\ufeff", "\u202e", "\u0661", "C:\\", "\\\\", "//", "__",
    };

    /// <summary>Any text: plain ASCII with control characters, any UTF-16 at all, or punctuation mixed with either.</summary>
    public static Arbitrary<string> Text { get; } = Arb.From(
        Gen.OneOf(
            ArbMap.Default.GeneratorFor<string>().Select(text => text ?? ""),
            Gen.Choose(0, char.MaxValue).Select(code => (char)code).ArrayOf().Select(chars => new string(chars)),
            Gen.OneOf(Gen.Elements(Punctuation), ArbMap.Default.GeneratorFor<string>().Select(text => text ?? ""))
                .ArrayOf().Select(string.Concat)),
        text => ArbMap.Default.ArbFor<string>().Shrinker(text).Where(smaller => smaller is not null));

    /// <summary>Any bytes: arbitrary ones, or any text as UTF-8.</summary>
    public static Arbitrary<byte[]> Bytes { get; } = Arb.From(
        Gen.OneOf(ArbMap.Default.GeneratorFor<byte[]>().Select(bytes => bytes ?? Array.Empty<byte>()), Text.Generator.Select(Encoding.UTF8.GetBytes)),
        bytes => ArbMap.Default.ArbFor<byte[]>().Shrinker(bytes).Where(smaller => smaller is not null));

    /// <summary>Text made of a format's own words, punctuation and plain text, so that some of it gets past the first check of a parser.</summary>
    public static Arbitrary<string> TextOf(params string[] words) => Arb.From(
        Gen.OneOf(
            Gen.OneOf(Gen.Elements(words), Gen.Elements(words), Gen.Elements(Punctuation), ArbMap.Default.GeneratorFor<string>().Select(text => text ?? ""))
                .ArrayOf().Select(string.Concat),
            Text.Generator),
        Text.Shrinker);

    /// <summary>
    /// JSON documents, mostly well formed, whose names and text come from
    /// <paramref name="words"/> or are any text at all, with values of every
    /// kind where a reader expects one kind. One in five is any text instead.
    /// </summary>
    public static Arbitrary<string> Json(params string[] words)
    {
        var text = Gen.OneOf(Gen.Elements(words), Gen.Elements(words), Gen.Elements(words), Text.Generator);
        var scalar = Gen.OneOf(
            Gen.Elements("null", "true", "false", "0", "1", "-1", "4", "2147483648", "9223372036854775808", "0.5", "1e999", "\"\"", "{}", "[]"),
            text.Select(FuzzRandom.JsonString),
            text.Select(FuzzRandom.JsonString));
        Gen<string> Value(int depth)
        {
            if (depth == 0) return scalar;
            var member = from name in text from value in Value(depth - 1) select FuzzRandom.JsonString(name) + ":" + value;
            var composite = from count in Gen.Choose(0, 4)
                            from members in member.ArrayOf(count)
                            from items in Value(depth - 1).ArrayOf(count)
                            from isObject in Gen.Elements(true, true, false)
                            select isObject ? "{" + string.Join(",", members) + "}" : "[" + string.Join(",", items) + "]";
            return Gen.OneOf(composite, composite, scalar);
        }
        var document = from depth in Gen.Choose(1, 4) from value in Value(depth) select value;
        return Arb.From(Gen.OneOf(document, document, document, document, TextOf(words).Generator), Text.Shrinker);
    }

    /// <summary>
    /// Checks a property against <paramref name="cases"/> inputs (times
    /// <see cref="Fuzzer.Scale"/>), the same ones for the same
    /// <see cref="Fuzzer.Seed"/>. The property fails by throwing.
    /// </summary>
    public static void Check<T>(string name, int cases, Arbitrary<T> inputs, Action<T> property)
    {
        unchecked
        {
            var seed = 14695981039346656037UL;
            foreach (var c in name) seed = (seed ^ c) * 1099511628211UL;
            seed += (ulong)Fuzzer.Seed * 0x9E3779B97F4A7C15UL;
            var config = Config.QuickThrowOnFailure
                .WithMaxTest((int)Math.Min(int.MaxValue, (long)cases * Fuzzer.Scale))
                .WithEndSize(200)
                .WithReplay(seed, 1UL);
            try
            {
                Prop.ForAll(inputs, input => { property(input); return true; }).Check(config);
            }
            catch (Exception ex)
            {
                throw new FuzzFailureException(
                    $"FsCheck found an input that fails \"{name}\" (seed {Fuzzer.Seed}).\n" +
                    $"Reproduce: {Fuzzer.SeedVariable}={Fuzzer.Seed} {Fuzzer.ScaleVariable}={Fuzzer.Scale} dotnet test tests/WatchLattice.Fuzz.Tests --filter \"FullyQualifiedName~ArbitraryInput\"\n" +
                    ex.Message, ex);
            }
        }
    }
}
