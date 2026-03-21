package ai.cyberarmor.rasp;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;

/**
 * Canonical CyberArmor javaagent entrypoint.
 *
 * Delegates to legacy CyberArmor implementation for one migration cycle.
 */
public final class CyberArmorAgent {
    private CyberArmorAgent() {}

    public static void premain(String agentArgs, Instrumentation inst) {
        invoke("premain", agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        invoke("agentmain", agentArgs, inst);
    }

    private static void invoke(String methodName, String agentArgs, Instrumentation inst) {
        try {
            Class<?> legacy = Class.forName("ai.cyberarmor.rasp.CyberArmorLegacyAgent");
            Method m = legacy.getMethod(methodName, String.class, Instrumentation.class);
            m.invoke(null, agentArgs, inst);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to delegate to legacy CyberArmor agent", ex);
        }
    }
}
