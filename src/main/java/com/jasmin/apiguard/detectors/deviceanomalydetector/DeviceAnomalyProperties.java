package com.jasmin.apiguard.detectors.deviceanomalydetector;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.device-anomaly")
public class DeviceAnomalyProperties {

    /** Identity extraction (ordered; first non-empty wins) */
    private List<String> identifierHeaderCandidates = new ArrayList<>(List.of("x-vendor-id", "x-fingerprint-id"));
    private boolean includeUserAgentInPrincipal = false;
    private boolean fallbackToIp = false;

    /** Bypass */
    private List<String> allowlistIdentifiers = new ArrayList<>();
    private List<String> allowlistIps = new ArrayList<>();
    private List<String> excludePatterns = new ArrayList<>(List.of("/health", "/metrics"));

    /** Window & thresholds */
    private int windowSeconds = 10 * 60;   // 10 minutes
    private int distinctIpThreshold = 4;   // >= 4 IPs in window → fan-out trip
    private int ipSwitchThreshold = 6;     // >= 6 IP switches in window → churn trip
    private int coolOffSeconds = 120;      // lock TTL when we BLOCK

    /** Actions */
    private List<String> actionsOnFanout = new ArrayList<>(List.of("CHALLENGE_MFA", "RATE_LIMIT"));
    private List<String> actionsOnChurn  = new ArrayList<>(List.of("CHALLENGE_CAPTCHA"));
    private List<String> actionsDuringLock = new ArrayList<>(List.of("RATE_LIMIT"));

    private int maxIpsPerDevice = 2;

    private boolean enabled = true;
}
