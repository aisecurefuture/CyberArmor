using System.Threading;
using System.Threading.Tasks;

namespace CyberArmor.Frameworks;

/// <summary>
/// Abstraction for LlamaIndex-style query execution.
/// </summary>
public interface ILlamaIndexQueryEngine
{
    Task<string> QueryAsync(string query, CancellationToken cancellationToken = default);
}
