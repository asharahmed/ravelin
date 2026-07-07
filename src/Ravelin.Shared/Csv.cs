using System.Text;

namespace Ravelin.Shared;

/// <summary>RFC 4180 CSV helpers used by the client export features.</summary>
public static class Csv
{
    /// <summary>Escapes a single field: neutralizes spreadsheet formula triggers, then quotes it
    /// when it contains a comma, quote, or newline. Finding fields (titles, package names) come
    /// from untrusted scan payloads, so a value like <c>=HYPERLINK(...)</c> or <c>=cmd|'/c calc'!A1</c>
    /// must not execute when an auditor opens the export in Excel/Sheets (CSV formula injection).</summary>
    public static string Field(string? value)
    {
        value ??= string.Empty;

        // Prefix a single quote if the value could be interpreted as a formula. The leading
        // characters that trigger evaluation in Excel/Google Sheets/LibreOffice are = + - @,
        // plus tab and carriage return.
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            value = "'" + value;
        }

        var mustQuote = value.Contains(',') || value.Contains('"')
            || value.Contains('\n') || value.Contains('\r');
        return mustQuote ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }

    /// <summary>Joins fields into one CSV record, escaping each.</summary>
    public static string Row(params string?[] fields) =>
        string.Join(",", fields.Select(Field));
}
