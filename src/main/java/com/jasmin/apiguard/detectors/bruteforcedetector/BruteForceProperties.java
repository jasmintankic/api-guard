package com.jasmin.apiguard.detectors.bruteforcedetector;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Positive;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.bruteforce")
public class BruteForceProperties {

    /** Per-scope thresholds. */
    private final BruteForceThreshold threshold = new BruteForceThreshold();

    /** Sliding window length (minutes) to aggregate across buckets. */
    @Min(1)
    private int windowMinutes = 5;

    /** Each bucket’s duration in minutes (granularity). */
    @Min(1)
    private int bucketMinutes = 1;

    /** TTL for per-bucket keys (minutes). Keep > windowMinutes. */
    @Min(1)
    private int expiryMinutes = 12;

    /** Cool-off lock TTL (seconds) when threshold trips. */
    @Positive
    private int coolOffSeconds = 60;
}
