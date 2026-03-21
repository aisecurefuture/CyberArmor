package ai.cyberarmor.frameworks;

import java.util.Objects;

/**
 * Typed framework guard helpers that wrap first-party framework interfaces.
 */
public final class CyberArmorFrameworkGuards {

    private CyberArmorFrameworkGuards() {
    }

    public static String guardLlamaIndex(CyberArmorLlamaIndexAdapter adapter, LlamaIndexEngine engine, String input) {
        Objects.requireNonNull(adapter, "adapter must not be null");
        Objects.requireNonNull(engine, "engine must not be null");
        return adapter.query(input, engine::query);
    }

    public static String guardVercelAI(CyberArmorVercelAIAdapter adapter, VercelAIEngine engine, String input) {
        Objects.requireNonNull(adapter, "adapter must not be null");
        Objects.requireNonNull(engine, "engine must not be null");
        return adapter.generate(input, engine::generate);
    }
}
