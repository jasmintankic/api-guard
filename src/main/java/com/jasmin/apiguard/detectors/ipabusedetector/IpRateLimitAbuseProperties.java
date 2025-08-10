package com.jasmin.apiguard.detectors.ipabusedetector;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.ip-rate-limit-abuse")
public class IpRateLimitAbuseProperties {

    /** Principal: ip:<ip> or ipua:<ip>:<uaHash> if true */
    private boolean includeUserAgentInPrincipal = false;

    /** Allowlist of principals or raw IPs that bypass detection */
    private List<String> allowlist = List.of();

    /** Ant-style path patterns that should not count (health, metrics, static, etc.) */
    private List<String> excludePatterns = List.of();

    /* ---------- Request-credit model (token-bucket style) ---------- */

    /** Credits added per second (sustained rate). Example: 2.0 ~= 2 req/s if creditsPerRequest=1 */
    @Positive
    private double creditsPerSecond = 2.0;

    /** Max credits a principal can hold (burst size ceiling). Example: 10 allows ~10 instant requests */
    @Positive
    private double maxCredits = 10.0;

    /** Credits consumed by a single request. Typically 1. */
    @Min(1)
    private int creditsPerRequest = 1;

    /** Idle TTL for the Redis key (cleanup only; does not affect decisions) */
    private Duration idleTtl = Duration.ofMinutes(30);

    /* ---------- Cool-off & escalation ---------- */

    /** Lock duration (seconds) after a denial */
    @Min(1)
    private int coolOffSeconds = 30;

    /** Optional: escalate lock if repeated denials occur within strikeWindowSeconds */
    private boolean strikeEscalationEnabled = true;

    /** Window to accumulate strikes */
    @Min(1)
    private int strikeWindowSeconds = 600; // 10 minutes

    /** Lock durations by strike level (1,2,>=3) */
    @Min(1)
    private int strike1LockSeconds = 30;

    @Min(1)
    private int strike2LockSeconds = 300;

    @Min(1)
    private int strike3LockSeconds = 3600;
}