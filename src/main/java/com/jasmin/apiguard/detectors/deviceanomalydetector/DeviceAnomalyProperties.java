package com.jasmin.apiguard.detectors.deviceanomalydetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.device-anomaly")
public class DeviceAnomalyProperties {

    /** Sliding window length in minutes (sum across buckets). */
    @Min(1) private int windowMinutes = 10;

    /** Bucket granularity in minutes. */
    @Min(1) private int bucketMinutes = 1;

    /** TTL for per-bucket sets (minutes). Keep > windowMinutes to cover lag. */
    @Min(1) private int expiryMinutes = 30;

    /** Lock duration (seconds) when a threshold trips. */
    @Min(1) private int coolOffSeconds = 300;

    /** Thresholds (distinct counts over the window). */
    @Min(1) private int thresholdUsersPerDevice = 5;   // device -> many users
    @Min(1) private int thresholdDevicesPerUser = 4;   // user -> many devices
    @Min(1) private int thresholdIpsPerDevice   = 6;   // device -> many IPs

    /** Include UA hash in device principal to reduce NAT false positives. */
    private boolean includeUserAgentInPrincipal = true;

    /** Header names (case-insensitive) to read device identifiers from. */
    private List<String> vendorIdHeaderNames = List.of("X-Vendor-Id", "Vendor-Id", "Device-Id");
    private List<String> fingerprintHeaderNames = List.of("X-Fingerprint", "Fingerprint", "Browser-Fingerprint");
}
