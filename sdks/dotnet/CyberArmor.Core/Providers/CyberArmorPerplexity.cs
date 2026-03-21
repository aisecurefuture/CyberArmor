using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenAI.Chat;

namespace CyberArmor.Providers;

/// <summary>Perplexity wrapper via OpenAI-compatible endpoint/gateway.</summary>
public sealed class CyberArmorPerplexity
{
    private readonly CyberArmorOpenAI _delegate;

    public CyberArmorPerplexity(CyberArmorClient client, string apiKey, string model = "sonar")
    {
        _delegate = new CyberArmorOpenAI(client, apiKey, model);
    }

    public Task<ChatCompletion> CompleteChatAsync(
        IEnumerable<ChatMessage> messages,
        string? tenantId = null,
        ChatCompletionOptions? options = null,
        CancellationToken ct = default)
        => _delegate.CompleteChatAsync(messages, tenantId, options, ct);
}

