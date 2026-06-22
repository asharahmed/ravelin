using System.Text;

namespace Ravelin.Shared;

/// <summary>RFC 4180 CSV helpers used by the client export features.</summary>
public static class Csv
{
    /// <summary>Escapes a single field: quotes it when it contains a comma, quote, or newline.</summary>
    public static string Field(string? value)
    {
        value ??= string.Empty;
        var mustQuote = value.Contains(',') || value.Contains('"')
            || value.Contains('\n') || value.Contains('\r');
        return mustQuote ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }

    /// <summary>Joins fields into one CSV record, escaping each.</summary>
    public static string Row(params string?[] fields) =>
        string.Join(",", fields.Select(Field));
}
