namespace Ravelin.Client.Services;

public enum ToastKind { Success, Error, Info }

public sealed record Toast(Guid Id, string Message, ToastKind Kind);

/// <summary>
/// A tiny client-side toast queue. Components subscribe to <see cref="OnChange"/> and render
/// the current <see cref="Toasts"/>; the host component owns auto-dismissal timing.
/// </summary>
public sealed class ToastService
{
    private readonly List<Toast> _toasts = new();

    public IReadOnlyList<Toast> Toasts => _toasts;
    public event Action? OnChange;

    /// <summary>Default time a toast stays before auto-dismiss.</summary>
    public TimeSpan DefaultDuration { get; } = TimeSpan.FromSeconds(4);

    public Toast Show(string message, ToastKind kind = ToastKind.Success)
    {
        var toast = new Toast(Guid.NewGuid(), message, kind);
        _toasts.Add(toast);
        OnChange?.Invoke();
        return toast;
    }

    public void Success(string message) => Show(message, ToastKind.Success);
    public void Error(string message) => Show(message, ToastKind.Error);
    public void Info(string message) => Show(message, ToastKind.Info);

    public void Remove(Guid id)
    {
        var removed = _toasts.RemoveAll(t => t.Id == id);
        if (removed > 0) OnChange?.Invoke();
    }
}
