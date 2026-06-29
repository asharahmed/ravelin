using Ravelin.Domain.Diagnostics;

namespace Ravelin.Tests;

public class SecretScrubberTests
{
    [Fact]
    public void Redacts_ravelin_api_key()
    {
        var input = "ingest failed for key rvln_abcdEFGH1234_-zz while parsing";
        var scrubbed = SecretScrubber.Scrub(input);
        Assert.DoesNotContain("rvln_abcdEFGH1234", scrubbed);
        Assert.Contains("[redacted]", scrubbed);
    }

    [Fact]
    public void Redacts_bearer_token_but_keeps_scheme()
    {
        var scrubbed = SecretScrubber.Scrub("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload");
        Assert.Contains("Bearer [redacted]", scrubbed);
        Assert.DoesNotContain("payload", scrubbed);
    }

    [Fact]
    public void Redacts_jwt()
    {
        var jwt = "aaaaaaaa.bbbbbbbb.cccccccc";
        Assert.DoesNotContain(jwt, SecretScrubber.Scrub($"token was {jwt} here"));
    }

    [Fact]
    public void Redacts_long_high_entropy_token()
    {
        var secret = "QWxhZGRpbjpvcGVuc2VzYW1lQWJjZGVmZ2hpamtsbW5v"; // 44 base64 chars
        Assert.DoesNotContain(secret, SecretScrubber.Scrub($"conn secret={secret};"));
    }

    [Fact]
    public void Leaves_ordinary_text_unchanged()
    {
        const string ordinary = "Object reference not set to an instance of an object.";
        Assert.Equal(ordinary, SecretScrubber.Scrub(ordinary));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Passes_through_null_or_empty(string? input)
    {
        Assert.Equal(input, SecretScrubber.Scrub(input));
    }
}

public class ErrorFingerprintTests
{
    private const string Stack1 =
        "   at Ravelin.Foo.Bar() in /src/Foo.cs:line 10\n   at Ravelin.Foo.Baz() in /src/Foo.cs:line 20";

    // Same frames, different line numbers (an unrelated edit shifted them).
    private const string Stack2 =
        "   at Ravelin.Foo.Bar() in /src/Foo.cs:line 88\n   at Ravelin.Foo.Baz() in /src/Foo.cs:line 200";

    [Fact]
    public void Same_fault_is_stable_across_line_number_shifts()
    {
        Assert.Equal(
            ErrorFingerprint.Compute("System.InvalidOperationException", Stack1),
            ErrorFingerprint.Compute("System.InvalidOperationException", Stack2));
    }

    [Fact]
    public void Different_exception_type_yields_different_fingerprint()
    {
        Assert.NotEqual(
            ErrorFingerprint.Compute("System.InvalidOperationException", Stack1),
            ErrorFingerprint.Compute("System.NullReferenceException", Stack1));
    }

    [Fact]
    public void Different_frames_yield_different_fingerprint()
    {
        var other = "   at Ravelin.Other.Method() in /src/Other.cs:line 5";
        Assert.NotEqual(
            ErrorFingerprint.Compute("System.Exception", Stack1),
            ErrorFingerprint.Compute("System.Exception", other));
    }

    [Fact]
    public void NormalizeFrames_strips_file_and_line_and_caps_count()
    {
        var deepStack = string.Join('\n',
            Enumerable.Range(1, 12).Select(i => $"   at Ravelin.T.M{i}() in /src/T.cs:line {i}"));

        var normalized = ErrorFingerprint.NormalizeFrames(deepStack);

        Assert.DoesNotContain(" in ", normalized);
        Assert.DoesNotContain(":line", normalized);
        Assert.Equal(5, normalized.Split('\n').Length); // top frames only
        Assert.Contains("at Ravelin.T.M1()", normalized);
    }

    [Fact]
    public void NormalizeFrames_handles_empty()
    {
        Assert.Equal(string.Empty, ErrorFingerprint.NormalizeFrames(null));
        Assert.Equal(string.Empty, ErrorFingerprint.NormalizeFrames("   "));
    }
}
