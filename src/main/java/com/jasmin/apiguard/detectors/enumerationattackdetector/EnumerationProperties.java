package com.jasmin.apiguard.detectors.enumerationattackdetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.enumeration")
public class EnumerationProperties {

    /** Unique usernames threshold within the sliding window to consider enumeration. */
    @Min(1)
    private int threshold = 20;

    /** Window length (minutes) to union HLL buckets across. */
    @Min(1)
    private int windowMinutes = 5;

    /** Bucket granularity (minutes). Keep 1 to match minute resolution. */
    @Min(1)
    private int bucketMinutes = 1;

    /** TTL for per-bucket HLL keys (minutes). Keep > windowMinutes. */
    @Min(1)
    private int expiryMinutes = 12;

    /** Cool-off lock duration (seconds) after threshold trips. */
    @Min(1)
    private int coolOffSeconds = 120;

    /** If true, key principals by IP+UserAgent to reduce NAT false positives. */
    private boolean includeUserAgentInPrincipal = true;
}
