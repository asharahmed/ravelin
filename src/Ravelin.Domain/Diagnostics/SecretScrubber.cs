using System.Text.RegularExpressions;

namespace Ravelin.Domain.Diagnostics;

/// <summary>
/// Removes secret-shaped substrings (Ravelin API keys, bearer tokens, JWTs, long high-entropy
/// runs) from text before it is persisted as a captured error or sent to an external tracker.
/// Capturing a bug requires capturing the inputs that triggered it — so the capture sink must
/// uphold the same "never store/log secrets" rule as the rest of the app. Conservative by
/// design: when a value looks like a credential, it is redacted.
/// </summary>
public static class SecretScrubber
{
    private const string Redacted = "[redacted]";

    // Ravelin API keys: the "rvln_" prefix followed by base64url.
    private static readonly Regex ApiKey = new(@"rvln_[A-Za-z0-9_\-]{8,}", RegexOptions.Compiled);

    // "Authorization: Bearer <token>" — keep the scheme word, drop the token.
    private static readonly Regex Bearer =
        new(@"Bearer\s+[A-Za-z0-9_\-\.=]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // JWT: three base64url segments separated by dots.
    private static readonly Regex Jwt =
        new(@"\b[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", RegexOptions.Compiled);

    // Generic long high-entropy token (base64/connection-string secret/key material).
    private static readonly Regex LongToken =
        new(@"\b[A-Za-z0-9+/]{32,}={0,2}\b", RegexOptions.Compiled);

    /// <summary>Returns the input with credential-shaped substrings replaced by a redaction
    /// marker. Null/empty passes through unchanged.</summary>
    public static string? Scrub(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        var s = ApiKey.Replace(input, Redacted);
        s = Bearer.Replace(s, $"Bearer {Redacted}");
        s = Jwt.Replace(s, Redacted);
        s = LongToken.Replace(s, Redacted);
        return s;
    }
}
