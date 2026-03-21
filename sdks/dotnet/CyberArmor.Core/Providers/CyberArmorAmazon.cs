using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenAI.Chat;

namespace CyberArmor.Providers;

/// <summary>Amazon Bedrock wrapper via OpenAI-compatible endpoint/gateway.</summary>
public sealed class CyberArmorAmazon
{
    private readonly CyberArmorOpenAI _delegate;

    public CyberArmorAmazon(CyberArmorClient client, string apiKey, string model = "amazon.nova-lite-v1:0")
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

