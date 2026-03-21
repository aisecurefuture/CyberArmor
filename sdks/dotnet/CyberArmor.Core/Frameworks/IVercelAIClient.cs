using System.Threading;
using System.Threading.Tasks;

namespace CyberArmor.Frameworks;

/// <summary>
/// Abstraction for Vercel-AI-style text generation.
/// </summary>
public interface IVercelAIClient
{
    Task<string> GenerateAsync(string input, CancellationToken cancellationToken = default);
}
