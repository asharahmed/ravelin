namespace Ravelin.Domain.Enums;

/// <summary>
/// How a scan's results entered the system. v1 supports pipeline push; manual upload and
/// pull-based sources are planned later (see PROJECT_VISION.md).
/// </summary>
public enum ScanSource
{
    PipelinePush = 0,
    ManualUpload = 1,
}
