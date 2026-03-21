using System.Threading;
using System.Threading.Tasks;

namespace CyberArmor.Frameworks;

/// <summary>
/// Abstraction for Semantic-Kernel-compatible prompt execution.
/// </summary>
public interface ISemanticKernelExecutor
{
    Task<string> InvokePromptAsync(string prompt, CancellationToken cancellationToken = default);
}
