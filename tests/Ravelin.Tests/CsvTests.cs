using Ravelin.Shared;
using Xunit;

namespace Ravelin.Tests;

public class CsvTests
{
    [Fact]
    public void Field_passes_through_plain_values()
    {
        Assert.Equal("Critical", Csv.Field("Critical"));
        Assert.Equal("CVE-2023-1234", Csv.Field("CVE-2023-1234"));
    }

    [Fact]
    public void Field_quotes_values_with_commas()
    {
        Assert.Equal("\"a, b\"", Csv.Field("a, b"));
    }

    [Fact]
    public void Field_escapes_embedded_quotes_and_wraps()
    {
        Assert.Equal("\"he said \"\"hi\"\"\"", Csv.Field("he said \"hi\""));
    }

    [Fact]
    public void Field_quotes_values_with_newlines()
    {
        Assert.Equal("\"line1\nline2\"", Csv.Field("line1\nline2"));
    }

    [Fact]
    public void Field_treats_null_as_empty()
    {
        Assert.Equal(string.Empty, Csv.Field(null));
    }

    [Fact]
    public void Row_joins_and_escapes_each_field()
    {
        Assert.Equal("High,\"netty, codec\",4.1.0", Csv.Row("High", "netty, codec", "4.1.0"));
    }

    [Fact]
    public void Row_handles_null_fields()
    {
        Assert.Equal("a,,c", Csv.Row("a", null, "c"));
    }

    [Theory]
    [InlineData("=HYPERLINK(\"http://evil\")", "'=HYPERLINK(\"http://evil\")")]
    [InlineData("+1+1", "'+1+1")]
    [InlineData("-2+3", "'-2+3")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    public void Field_neutralizes_formula_injection_triggers(string input, string expectedInner)
    {
        // Untrusted scan fields (titles, package names) must not evaluate as spreadsheet formulas
        // when an auditor opens the export. Values with a comma/quote are additionally RFC 4180
        // quoted around the neutralized value.
        var result = Csv.Field(input);
        var unquoted = result.StartsWith('"') ? result[1..^1].Replace("\"\"", "\"") : result;
        Assert.Equal(expectedInner, unquoted);
    }

    [Fact]
    public void Field_neutralizes_the_classic_dde_command_payload()
    {
        // Leading '=' is neutralized with a leading apostrophe; the payload has no comma/quote/
        // newline, so no RFC 4180 wrapping is added.
        Assert.Equal("'=cmd|'/c calc'!A1", Csv.Field("=cmd|'/c calc'!A1"));
    }
}
