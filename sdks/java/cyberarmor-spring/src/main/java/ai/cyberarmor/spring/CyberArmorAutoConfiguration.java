package ai.cyberarmor.spring;

import ai.cyberarmor.CyberArmorClient;
import ai.cyberarmor.config.CyberArmorConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot 3.x autoconfiguration for CyberArmor.
 *
 * <p>Automatically creates a {@link CyberArmorClient} bean when:
 * <ul>
 *   <li>{@code cyberarmor.enabled=true} (default)</li>
 *   <li>{@link CyberArmorClient} is on the classpath</li>
 *   <li>No existing {@link CyberArmorClient} bean is present</li>
 * </ul>
 *
 * <p>Register via {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.
 */
@AutoConfiguration
@ConditionalOnClass(CyberArmorClient.class)
@ConditionalOnProperty(prefix = "cyberarmor", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(CyberArmorProperties.class)
public class CyberArmorAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(CyberArmorAutoConfiguration.class);

    /**
     * Create the {@link CyberArmorConfig} bean from Spring Boot properties.
     */
    @Bean
    @ConditionalOnMissingBean(CyberArmorConfig.class)
    public CyberArmorConfig cyberArmorConfig(CyberArmorProperties properties) {
        CyberArmorConfig config = new CyberArmorConfig();
        config.setControlPlaneUrl(properties.getControlPlaneUrl());
        config.setAgentId(properties.getAgentId());
        config.setAgentSecret(properties.getAgentSecret());
        config.setEnforceMode(properties.getEnforceMode());
        config.setTimeoutMs(properties.getTimeoutMs());
        config.setAuditBatchSize(properties.getAuditBatchSize());
        config.setFailOpen(properties.isFailOpen());
        config.setTenantId(properties.getTenantId());
        config.setEnvironment(properties.getEnvironment());
        config.setAuditFlushIntervalSeconds(properties.getAuditFlushIntervalSeconds());

        log.info("CyberArmor configured: controlPlaneUrl={} agentId={} enforceMode={} environment={}",
                config.getControlPlaneUrl(), config.getAgentId(),
                config.getEnforceMode(), config.getEnvironment());
        return config;
    }

    /**
     * Create the singleton {@link CyberArmorClient} bean.
     *
     * <p>The client is an {@link AutoCloseable}; Spring will call {@code close()}
     * on it during context shutdown via {@code destroyMethod}.
     */
    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(CyberArmorClient.class)
    public CyberArmorClient cyberArmorClient(CyberArmorConfig config) {
        log.info("Initializing CyberArmorClient Spring bean");
        return CyberArmorClient.builder()
                .controlPlaneUrl(config.getControlPlaneUrl())
                .agentId(config.getAgentId())
                .agentSecret(config.getAgentSecret())
                .enforceMode(config.getEnforceMode())
                .timeoutMs(config.getTimeoutMs())
                .auditBatchSize(config.getAuditBatchSize())
                .failOpen(config.isFailOpen())
                .build();
    }
}
