using System;
using System.Threading;
using System.Threading.Tasks;

namespace CyberArmor.Frameworks;

/// <summary>
/// Typed framework guard helpers that wrap first-party framework interfaces.
/// </summary>
public static class CyberArmorFrameworkGuards
{
    public static Task<string> GuardSemanticKernelAsync(
        this CyberArmorSemanticKernel guard,
        ISemanticKernelExecutor executor,
        string prompt,
        CancellationToken ct = default)
    {
        if (executor is null) throw new ArgumentNullException(nameof(executor));
        return guard.InvokeAsync(prompt, (p, token) => executor.InvokePromptAsync(p, token), ct);
    }

    public static Task<string> GuardLlamaIndexAsync(
        this CyberArmorLlamaIndex guard,
        ILlamaIndexQueryEngine engine,
        string query,
        CancellationToken ct = default)
    {
        if (engine is null) throw new ArgumentNullException(nameof(engine));
        return guard.QueryAsync(query, (q, token) => engine.QueryAsync(q, token), ct);
    }

    public static Task<string> GuardVercelAIAsync(
        this CyberArmorVercelAI guard,
        IVercelAIClient client,
        string input,
        CancellationToken ct = default)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        return guard.GenerateAsync(input, (s, token) => client.GenerateAsync(s, token), ct);
    }
}
