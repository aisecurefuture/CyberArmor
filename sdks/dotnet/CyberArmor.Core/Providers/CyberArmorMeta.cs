using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenAI.Chat;

namespace CyberArmor.Providers;

/// <summary>Meta wrapper via OpenAI-compatible endpoint/gateway.</summary>
public sealed class CyberArmorMeta
{
    private readonly CyberArmorOpenAI _delegate;

    public CyberArmorMeta(CyberArmorClient client, string apiKey, string model = "llama-3.3-70b-instruct")
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

