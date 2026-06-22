namespace Ravelin.Domain.Ingestion;

using System.Text.Json;

/// <summary>Small, null-tolerant helpers shared by the scanner adapters.</summary>
internal static class ScanJson
{
    /// <summary>Reads a string property, or null if absent / not a string / blank.</summary>
    public static string? Str(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object
        && obj.TryGetProperty(name, out var p)
        && p.ValueKind == JsonValueKind.String
        && !string.IsNullOrWhiteSpace(p.GetString())
            ? p.GetString()
            : null;

    /// <summary>First non-blank candidate, or the final fallback.</summary>
    public static string FirstNonEmpty(string? a, string? b, string fallback) =>
        !string.IsNullOrWhiteSpace(a) ? a! : !string.IsNullOrWhiteSpace(b) ? b! : fallback;

    /// <summary>Trims a description to a usable title length on a word boundary.</summary>
    public static string? Truncate(string? text, int max)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        text = text.Trim().ReplaceLineEndings(" ");
        if (text.Length <= max) return text;
        var cut = text.LastIndexOf(' ', Math.Min(max, text.Length - 1));
        return (cut > 40 ? text[..cut] : text[..max]).TrimEnd() + "…";
    }
}
