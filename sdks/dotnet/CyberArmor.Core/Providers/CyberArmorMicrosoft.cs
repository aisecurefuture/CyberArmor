using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using OpenAI.Chat;

namespace CyberArmor.Providers;

/// <summary>Microsoft/Azure wrapper via OpenAI-compatible endpoint/gateway.</summary>
public sealed class CyberArmorMicrosoft
{
    private readonly CyberArmorOpenAI _delegate;

    public CyberArmorMicrosoft(CyberArmorClient client, string apiKey, string model = "phi-4")
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

