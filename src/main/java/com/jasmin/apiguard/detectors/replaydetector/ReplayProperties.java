package com.jasmin.apiguard.detectors.replaydetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Set;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.replay")
public class ReplayProperties {

    /** Only protect these HTTP methods (mutating by default). */
    private Set<String> protectedMethods = Set.of("POST", "PUT", "PATCH", "DELETE");

    /** Idempotency window (milliseconds). Within this window, duplicates are rejected. */
    @Min(1000)
    private long windowMillis = 120_000;

    /** After this many duplicates for the same identity, cool-off the principal. */
    @Min(1)
    private int abuseThreshold = 3;

    /** Cool-off duration (seconds) for the principal (e.g., IP or IP+UA). */
    @Min(1)
    private int coolOffSeconds = 120;

    /** Principal granularity: include User-Agent alongside IP to reduce NAT false positives. */
    private boolean includeUserAgentInPrincipal = true;

    /** Max bytes of body to hash (caps CPU). */
    @Min(0)
    private int maxBodyBytes = 64 * 1024;

    /** Canonicalize JSON bodies (stable across whitespace/key-order). */
    private boolean canonicalizeJson = true;

    /** Header names considered as explicit idempotency keys (case-insensitive). */
    private Set<String> idempotencyHeaderNames = Set.of("Correlation-Id", "Idempotency-Key", "X-Request-Id");

    /** Query params to ignore during canonicalization (tracking/noise). */
    private Set<String> ignoredQueryParams = Set.of(
            "utm_source","utm_medium","utm_campaign","utm_term","utm_content","tracking_id"
    );
}
