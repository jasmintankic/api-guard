package com.jasmin.apiguard.detectors.enumerationattackdetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.enumeration")
public class EnumerationProperties {

    /** A) Unique usernames threshold within the sliding window to consider enumeration. */
    @Min(1)
    private int threshold = 20;

    /** A) Window length (minutes) to union HLL buckets across. */
    @Min(1)
    private int windowMinutes = 5;

    /** A+B) Bucket granularity (minutes). Keep 1 to match minute resolution. */
    @Min(1)
    private int bucketMinutes = 1;

    /** A) TTL for per-bucket HLL keys (minutes). Keep >= windowMinutes + bucketMinutes. */
    @Min(1)
    private int expiryMinutes = 12;

    /** Cool-off lock duration (seconds) after any signal trips. */
    @Min(1)
    private int coolOffSeconds = 120;

    /** If true, key principals by IP+UserAgent to reduce NAT false positives. */
    private boolean includeUserAgentInPrincipal = true;


    /** Threshold for distinct IPs probing the same username (within userIpsWindowMinutes). */
    @Min(1)
    private int userIpsThreshold = 30;

    /** Window length (minutes) for distinct IPs per username. */
    @Min(1)
    private int userIpsWindowMinutes = 15;

    /** TTL (minutes) for user-IPs HLL buckets. Keep >= userIpsWindowMinutes + bucketMinutes. */
    @Min(1)
    private int userIpsExpiryMinutes = 20;

    // ===== New: C) Per-principal raw request rate =====

    /** Max requests allowed per principal within ipRateWindowSeconds. */
    @Min(1)
    private int ipRateLimit = 90;

    /** Sliding window (seconds) for the per-principal raw request limiter. */
    @Min(1)
    private int ipRateWindowSeconds = 60;
}
