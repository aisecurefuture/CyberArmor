package ai.cyberarmor.providers;

import ai.cyberarmor.CyberArmorClient;
import ai.cyberarmor.policy.PolicyViolationException;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/** Amazon Bedrock wrapper via OpenAI-compatible gateway endpoint. */
public class CyberArmorAmazon {
    private static final String DEFAULT_BASE_URL = "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1";
    private final CyberArmorOpenAI delegate;

    public CyberArmorAmazon(CyberArmorClient cyberArmorClient, String apiKey) {
        this.delegate = new CyberArmorOpenAI(cyberArmorClient, apiKey, DEFAULT_BASE_URL);
    }

    public CyberArmorAmazon(CyberArmorClient cyberArmorClient, String apiKey, String baseUrl) {
        this.delegate = new CyberArmorOpenAI(cyberArmorClient, apiKey, baseUrl);
    }

    public JsonNode chatCompletions(String model, List<Map<String, Object>> messages,
                                    Map<String, Object> extraParams)
            throws IOException, PolicyViolationException {
        return delegate.chatCompletions(model, messages, extraParams);
    }
}

