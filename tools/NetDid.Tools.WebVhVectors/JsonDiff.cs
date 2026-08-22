using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace NetDid.Tools.WebVhVectors;

/// <summary>How a single JSON path in our output relates to what the other implementations emit.</summary>
public enum DivergenceKind
{
    /// <summary>Every implementation emits this path; we do not. Unambiguously ours to answer for.</summary>
    MissingFromOurs,

    /// <summary>No implementation emits this path; we do.</summary>
    ExtraInOurs,

    /// <summary>Every implementation agrees on a value; ours differs.</summary>
    ValueDiffersFromUnanimous,

    /// <summary>The implementations disagree among themselves — a spec ambiguity, not our defect.</summary>
    InterImplementationDisagreement,
}

public sealed record Divergence
{
    public required string Scenario { get; init; }
    public required string Target { get; init; }
    public required string Path { get; init; }
    public required DivergenceKind Kind { get; init; }
    public string? OurValue { get; init; }
    /// <summary>Value → implementations emitting it, for the reference implementations.</summary>
    public required IReadOnlyDictionary<string, IReadOnlyList<string>> ImplValues { get; init; }

    /// <summary>Path with per-item array keys collapsed, so findings group by root cause.</summary>
    public string ShapePath => Regex.Replace(Path, @"\[[^\]]*\]", "[]");
}

public static class JsonDiff
{
    private static readonly Regex VersionIdPattern = new(@"^(\d+)-[1-9A-HJ-NP-Za-km-z]{20,}$",
        RegexOptions.Compiled);

    /// <summary>
    /// Rewrites implementation-specific values into placeholders so results become comparable.
    /// Each implementation derives a different SCID for the same scenario (the SCID hashes the whole
    /// genesis entry, and serialization differs), which cascades into the DID and every entry hash.
    /// Key material does not vary — the suite derives all keys from fixed seeds.
    /// </summary>
    public static JsonNode? Normalize(JsonNode? node, string? scid)
    {
        switch (node)
        {
            case null:
                return null;

            case JsonObject obj:
            {
                var result = new JsonObject();
                foreach (var (key, value) in obj)
                    result[key] = Normalize(value, scid);
                return result;
            }

            case JsonArray arr:
            {
                var result = new JsonArray();
                foreach (var item in arr)
                    result.Add(Normalize(item, scid));
                return result;
            }

            default:
            {
                var value = node.ToJsonString();
                if (node is JsonValue v && v.TryGetValue<string>(out var s))
                {
                    if (!string.IsNullOrEmpty(scid))
                        s = s.Replace(scid, "{SCID}", StringComparison.Ordinal);
                    s = VersionIdPattern.Replace(s, "$1-{HASH}");
                    return JsonValue.Create(s);
                }
                return JsonNode.Parse(value);
            }
        }
    }

    /// <summary>
    /// Flattens JSON to path → value. Arrays of objects carrying an <c>id</c> are keyed by that id
    /// and arrays of scalars are sorted, so element ordering — which the suite does not constrain —
    /// never registers as a divergence.
    /// </summary>
    public static Dictionary<string, string> Flatten(JsonNode? node)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        Walk(node, "", map);
        return map;
    }

    private static string? Fragment(string? id)
    {
        if (id is null) return null;
        var hash = id.IndexOf('#');
        return hash >= 0 ? id[hash..] : id;
    }

    private static void Walk(JsonNode? node, string path, Dictionary<string, string> map)
    {
        switch (node)
        {
            case null:
                map[path] = "null";
                return;

            case JsonObject obj:
            {
                if (obj.Count == 0) { map[path] = "{}"; return; }
                foreach (var (key, value) in obj)
                    Walk(value, path.Length == 0 ? key : $"{path}.{key}", map);
                return;
            }

            case JsonArray arr:
            {
                if (arr.Count == 0) { map[path] = "[]"; return; }

                // Key by the id's fragment, not the whole id: implementations disagree over whether
                // an implicit service id is absolute ("did:webvh:…#files") or relative ("#files"),
                // and keying on the full value would split one entry across two paths and hide the
                // value difference behind a phantom presence difference.
                var ids = arr.Select(i => Fragment((i as JsonObject)?["id"]?.GetValue<string>())).ToList();
                if (ids.All(i => i is not null) && ids.Distinct(StringComparer.Ordinal).Count() == ids.Count)
                {
                    for (var i = 0; i < arr.Count; i++)
                        Walk(arr[i], $"{path}[id={ids[i]}]", map);
                    return;
                }

                if (arr.All(i => i is JsonValue))
                {
                    var values = arr.Select(i => i!.ToJsonString()).OrderBy(x => x, StringComparer.Ordinal);
                    map[path] = "[" + string.Join(",", values) + "]";
                    return;
                }

                for (var i = 0; i < arr.Count; i++)
                    Walk(arr[i], $"{path}[{i.ToString(CultureInfo.InvariantCulture)}]", map);
                return;
            }

            default:
                map[path] = node.ToJsonString();
                return;
        }
    }

    private const string Absent = "(absent)";

    /// <summary>
    /// Diffs our resolution of one implementation's log against <em>that same implementation's</em>
    /// committed result, then classifies each difference using how the other implementations behave
    /// in their own results.
    /// <para>
    /// The oracle must be the authoring implementation: every implementation derives a different
    /// SCID and makes different document-shaping choices, so diffing our output for one
    /// implementation's log against a second implementation's expectations would report their
    /// disagreement with each other as our defect. The peer results are used only to decide whether
    /// a genuine difference is universal (ours to answer for) or contested (spec ambiguity).
    /// </para>
    /// </summary>
    /// <param name="scenario">Scenario name, recorded on each divergence.</param>
    /// <param name="target">Expected-result file this comparison is against.</param>
    /// <param name="ours">Our resolution of <paramref name="oracleImpl"/>'s log.</param>
    /// <param name="oracleImpl">The implementation that authored the log we resolved.</param>
    /// <param name="byImpl">Every implementation's own committed result for this target.</param>
    public static IReadOnlyList<Divergence> Compare(
        string scenario,
        string target,
        Dictionary<string, string> ours,
        string oracleImpl,
        IReadOnlyDictionary<string, Dictionary<string, string>> byImpl)
    {
        var divergences = new List<Divergence>();
        if (!byImpl.TryGetValue(oracleImpl, out var oracle)) return divergences;

        var paths = new SortedSet<string>(StringComparer.Ordinal);
        paths.UnionWith(ours.Keys);
        paths.UnionWith(oracle.Keys);

        foreach (var path in paths)
        {
            var weHave = ours.TryGetValue(path, out var ourValue);
            var oracleHas = oracle.TryGetValue(path, out var oracleValue);

            // Agreement with the authoring implementation: nothing to report.
            if (weHave == oracleHas && ourValue == oracleValue) continue;

            // How every implementation behaves on this path in its own result. Omission is a
            // position, so it gets its own group rather than vanishing from the tally.
            var valueGroups = byImpl
                .GroupBy(kv => kv.Value.TryGetValue(path, out var v) ? v : Absent, StringComparer.Ordinal)
                .ToDictionary(
                    g => g.Key,
                    g => (IReadOnlyList<string>)g.Select(kv => kv.Key)
                        .OrderBy(x => x, StringComparer.Ordinal).ToList(),
                    StringComparer.Ordinal);

            var implsEmitting = byImpl.Count(kv => kv.Value.ContainsKey(path));
            var unanimous = valueGroups.Count == 1;

            var kind = (weHave, implsEmitting) switch
            {
                (false, var n) when n == byImpl.Count => DivergenceKind.MissingFromOurs,
                (true, 0) => DivergenceKind.ExtraInOurs,
                _ when unanimous => DivergenceKind.ValueDiffersFromUnanimous,
                _ => DivergenceKind.InterImplementationDisagreement,
            };

            divergences.Add(new Divergence
            {
                Scenario = scenario,
                Target = target,
                Path = path,
                Kind = kind,
                OurValue = weHave ? ourValue : null,
                ImplValues = valueGroups,
            });
        }

        return divergences;
    }
}
