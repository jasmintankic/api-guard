package com.jasmin.apiguard.detectors.ipabusedetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.ipabuse")
public class IpAbuseProperties {

    /** Aggregate window length in minutes (sum of buckets). */
    @Min(1) private int windowMinutes = 5;

    /** Bucket granularity in minutes. */
    @Min(1) private int bucketMinutes = 1;

    /** TTL for per-bucket keys (minutes). Keep > windowMinutes. */
    @Min(1) private int expiryMinutes = 12;

    /** Lock duration (seconds) when threshold trips. */
    @Min(1) private int coolOffSeconds = 120;

    /** Requests allowed per principal within the window (unweighted). */
    @Min(1) private int threshold = 300;

    /** If true, key principal as IP+UA hash to reduce NAT false positives. */
    private boolean includeUserAgentInPrincipal = true;

    /** Exact paths or ant patterns to exclude entirely (health, metrics, static). */
    private List<String> excludePatterns = List.of("/health", "/healthz", "/actuator/**", "/metrics", "/static/**");

    /** Map of ant patterns to integer weights (e.g., "/login"=3, "/admin/**"=5). Defaults to 1. */
    private Map<String,Integer> weightedPatterns = Map.of("/login", 3, "/reset-password", 3, "/admin/**", 5);

    /** Optional ip/UA allowlist (exact matches) that bypass this detector. */
    private List<String> allowlist = List.of();
}
