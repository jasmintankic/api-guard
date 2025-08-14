package com.jasmin.apiguard.detectors.enumerationattackdetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "detectors.enumeration")
public class EnumerationProperties {

    /** A) Unique usernames threshold within the sliding window to consider enumeration. */
    @Min(1)
    private int threshold = 20;

    /** A+B) Bucket granularity (minutes). Keep 1 to match minute resolution. */
    @Min(1)
    private int bucketMinutes = 1;

    /** Cool-off lock duration (seconds) after any signal trips. */
    @Min(1)
    private int coolOffSeconds = 120;

    /** If true, key principals by IP+UserAgent to reduce NAT false positives. */
    private boolean includeUserAgentInPrincipal = true;

    /** Threshold for distinct IPs probing the same username (within userIpsWindowMinutes). */
    @Min(1)
    private int userIpsThreshold = 30;

    // ===== New: C) Per-principal raw request rate =====

    /** Max requests allowed per principal within ipRateWindowSeconds. */
    @Min(1)
    private int ipRateLimit = 90;

    /** Sliding window (seconds) for the per-principal raw request limiter. */
    @Min(1)
    private int ipRateWindowSeconds = 60;

    private boolean enabled = true;
}
