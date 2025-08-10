package com.jasmin.apiguard.detectors.trafficanomalydetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.traffic-anomaly")
public class TrafficAnomalyProperties {

    /** EWMA smoothing factor (0..1). Higher = adapts faster; lower = smoother baseline. */
    private double alpha = 0.25;

    /** Z-score threshold to consider current minute a surge (e.g., 3.0 => 3σ above baseline). */
    private double zThreshold = 3.0;

    /** Require at least this many distinct IPs across the window to avoid single-client noise. */
    @Min(1) private int minDistinctIps = 50;

    /** Require at least this many distinct minute samples before allowing alerts (baseline warm-up). */
    @Min(1) private int minSampleMinutes = 5;

    /** Distinct-IP sliding window length in minutes (union of last N minute sets). */
    @Min(1) private int windowMinutes = 3;

    /** Minute bucket granularity. */
    @Min(1) private int bucketMinutes = 1;

    /** TTL for per-minute buckets (keep > windowMinutes). */
    @Min(1) private int expiryMinutes = 10;

    /** Cool-off duration for an endpoint once a surge is detected. */
    @Min(1) private int coolOffSeconds = 90;

    /** Paths to exclude from surge detection (health/metrics/static/etc.). */
    private List<String> excludePatterns = List.of("/health/**", "/metrics/**", "/static/**", "/favicon.*");
}
