package com.jasmin.apiguard.services.threatstore;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "threat-store")
public class ThreatStoreProperties {
    /**
     * How many days to keep threat events in Redis.
     */
    private int retentionDays = 10;

    /**
     * Max body size to store (bytes). Larger bodies will be truncated.
     */
    private int maxBodyBytes = 8192;

    /**
     * Which headers to keep in stored events.
     */
    private List<String> headerAllowlist = List.of(
            "content-type", "user-agent", "x-forwarded-for", "cf-connecting-ip", "x-request-id"
    );

    public Duration retentionDuration() {
        return Duration.ofDays(retentionDays);
    }
}