package com.jasmin.apiguard.detectors.ipabusedetector;

import lombok.Data;

import java.time.Duration;

@Data
public class IpAbuseScopeConfig {
    /**
     * Credits added per second (sustained rate).
     */
    private double creditsPerSecond = 2.0;

    /**
     * Max credits (burst ceiling).
     */
    private double maxCredits = 10.0;

    /**
     * Cost per request.
     */
    private int creditsPerRequest = 1;

    /**
     * Optional idle TTL for the Redis state key. If null, detector computes:
     * ceil( maxCredits / max(0.0001, creditsPerSecond) + 60s ),
     * clamped to [60s, 86400s].
     */
    private Duration idleTtl;
}
