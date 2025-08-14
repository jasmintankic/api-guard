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


    /** TTL for per-bucket keys (minutes). Keep > windowMinutes. */
    @Min(1)
    private int expiryMinutes = 12;

    /** Cool-off lock TTL (seconds) when threshold trips. */
    @Positive
    private int coolOffSeconds = 60;

    //Use seconds for the sliding window (ZSET-based)
    private int windowSeconds = 300; // e.g., 5 minutes

    private int maxEventsPerScope = 2000;

    private boolean enabled = true;
}
