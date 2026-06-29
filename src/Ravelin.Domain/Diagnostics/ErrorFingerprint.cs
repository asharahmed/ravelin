using System.Security.Cryptography;
using System.Text;

namespace Ravelin.Domain.Diagnostics;

/// <summary>
/// Computes a stable identity for an exception so the same fault always groups to one record,
/// however often it fires. Identity = SHA-256 of the exception type plus the top few stack
/// frames with volatile detail (file paths, line numbers) stripped — so an unrelated edit that
/// shifts line numbers doesn't fork the group, but two genuinely different faults stay distinct.
/// Pure: no I/O, fully unit-testable.
/// </summary>
public static class ErrorFingerprint
{
    private const int FramesUsed = 5;

    /// <summary>The normalized top frames used for grouping — also stored as the human-readable
    /// repro excerpt. "at Ns.Type.Method(args) in /path/File.cs:line 42" becomes
    /// "at Ns.Type.Method(args)".</summary>
    public static string NormalizeFrames(string? stackTrace)
    {
        if (string.IsNullOrWhiteSpace(stackTrace))
        {
            return string.Empty;
        }

        var frames = stackTrace
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.StartsWith("at ", StringComparison.Ordinal))
            .Take(FramesUsed)
            .Select(StripVolatile);

        return string.Join('\n', frames);
    }

    /// <summary>The stable fingerprint (SHA-256 hex) for (exception type, normalized frames).</summary>
    public static string Compute(string exceptionType, string? stackTrace)
    {
        var basis = exceptionType + "\n" + NormalizeFrames(stackTrace);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(basis)));
    }

    private static string StripVolatile(string frame)
    {
        // Drop the " in <file>:line <n>" suffix that varies with edits/builds.
        var inIndex = frame.IndexOf(" in ", StringComparison.Ordinal);
        return inIndex >= 0 ? frame[..inIndex] : frame;
    }
}
