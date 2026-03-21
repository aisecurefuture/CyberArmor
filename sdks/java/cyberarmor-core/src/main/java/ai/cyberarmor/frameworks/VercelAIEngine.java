package ai.cyberarmor.frameworks;

/**
 * First-party interface for Vercel-AI-style text generation engines in Java.
 */
@FunctionalInterface
public interface VercelAIEngine {
    String generate(String input);
}
