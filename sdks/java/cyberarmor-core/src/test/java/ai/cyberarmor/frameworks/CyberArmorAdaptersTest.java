package ai.cyberarmor.frameworks;

import ai.cyberarmor.CyberArmorClient;
import ai.cyberarmor.config.CyberArmorConfig;
import ai.cyberarmor.policy.Decision;
import ai.cyberarmor.policy.PolicyViolationException;
import org.junit.jupiter.api.Test;

import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CyberArmorAdaptersTest {

    @Test
    void llamaIndexAdapter_allowsAndEmitsAudit() {
        CyberArmorClient client = mock(CyberArmorClient.class);
        CyberArmorConfig cfg = new CyberArmorConfig();
        cfg.setEnforceMode("block");
        cfg.setTenantId("tenant-1");
        when(client.getConfig()).thenReturn(cfg);
        when(client.evaluatePolicy(any())).thenReturn(Decision.allow());

        CyberArmorLlamaIndexAdapter adapter =
                new CyberArmorLlamaIndexAdapter(client, "openai", "gpt-4o", "tenant-1");

        String out = adapter.query("hello", s -> "ok:" + s);
        assertEquals("ok:hello", out);
        verify(client, times(1)).emitEvent(eq("framework.llamaindex.query"), any());
    }

    @Test
    void vercelAdapter_blocksWhenDenied() {
        CyberArmorClient client = mock(CyberArmorClient.class);
        CyberArmorConfig cfg = new CyberArmorConfig();
        cfg.setEnforceMode("block");
        cfg.setTenantId("tenant-1");
        when(client.getConfig()).thenReturn(cfg);
        when(client.evaluatePolicy(any())).thenReturn(Decision.deny("TEST_DENY"));

        CyberArmorVercelAIAdapter adapter =
                new CyberArmorVercelAIAdapter(client, "openai", "gpt-4o", "tenant-1");

        Function<String, String> delegate = s -> "unused";
        assertThrows(PolicyViolationException.class, () -> adapter.generate("hello", delegate));
    }
}
