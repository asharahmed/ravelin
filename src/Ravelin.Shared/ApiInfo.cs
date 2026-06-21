namespace Ravelin.Shared;

/// <summary>
/// Lightweight service metadata returned by the <c>/api/info</c> endpoint.
/// Defined in the Shared project so the API (producer) and the Blazor client
/// (consumer) depend on one identical contract — the API-first principle in miniature.
/// </summary>
/// <param name="Name">Product name.</param>
/// <param name="Description">Short product description.</param>
/// <param name="Version">Assembly/informational version of the running API.</param>
/// <param name="Environment">Hosting environment name (Development, Production, ...).</param>
public record ApiInfo(string Name, string Description, string Version, string Environment);
