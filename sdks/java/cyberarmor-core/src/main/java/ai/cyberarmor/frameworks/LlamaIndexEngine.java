package ai.cyberarmor.frameworks;

/**
 * First-party interface for LlamaIndex-style query engines in Java.
 */
@FunctionalInterface
public interface LlamaIndexEngine {
    String query(String input);
}
