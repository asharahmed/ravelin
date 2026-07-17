namespace Ravelin.Auth;

/// <summary>How self-service account registration behaves. Defaults to Disabled — a real
/// deployment opts in; the public demo sets Mode=Open so anyone can create a read-only account.</summary>
public sealed class RegistrationOptions
{
    public const string SectionName = "Registration";

    public RegistrationMode Mode { get; set; } = RegistrationMode.Disabled;
}

public enum RegistrationMode
{
    /// <summary>No self-service registration; accounts are created by an administrator.</summary>
    Disabled = 0,

    /// <summary>Anyone may register (they get the read-only Viewer role). Used by the public demo.</summary>
    Open = 1,
}
