namespace Ravelin.Domain.Enums;

/// <summary>
/// Vulnerability severity. Integer values are ordered ascending so severities can be
/// compared (e.g. <c>>= Severity.High</c>) and mapped to SLA policies.
/// </summary>
public enum Severity
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
