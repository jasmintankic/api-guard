package com.jasmin.apiguard.detectors.ipabusedetector;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Set;

@Data
@Validated
@ConfigurationProperties(prefix = "detectors.ip-rate-limit-abuse")
public class IpRateLimitAbuseProperties {

    /** Master switch for the detector. */
    private boolean enabled = true;

    /** Whether to include UA hash as part of the principal (ipua:<ip>:<uaHash>). */
    private boolean includeUserAgentInPrincipal = false;

    /** Principals or raw IPs that bypass detection. */
    @NotNull
    private Set<String> allowlist = Set.of();

    /** Ant-style path patterns excluded from detection. */
    @NotNull
    private List<String> excludePatterns = List.of();

    /** If Redis/script errors occur: true = allow (fail-open), false = deny (fail-closed). */
    private boolean failOpenOnRedisError = true;

    /** Jitter fraction added to lock TTLs (e.g., 0.10 = up to +10%). Range [0.0, 1.0]. */
    @PositiveOrZero
    private double lockJitterPercent = 0.10;

    /* ------------------------- Strikes / Escalation ------------------------- */

    /** Enable strike-based escalation on the principal scope. */
    private boolean strikeEscalationEnabled = true;

    /** Window to accumulate strikes (seconds). */
    private int strikeWindowSeconds = 600;

    /** Lock seconds for strike 1 / 2 / >=3 (will be jittered). */
    private int strike1LockSeconds = 60;

    private int strike2LockSeconds = 300;

    private int strike3LockSeconds = 1800;

    /** Base cool-off seconds when a scope trips (used by UA/Subnet and as base for principal). */
    private int coolOffSeconds = 60;

    /* ------------------------- Subnet / UA toggles ------------------------- */

    private boolean subnetRateLimitEnabled = true;
    private boolean userAgentRateLimitEnabled = true;

    /** IPv4 CIDR prefix used for subnet grouping (default /24). */
    private int subnetIpv4Prefix = 24;

    /** IPv6 CIDR prefix used for subnet grouping (default /64). */
    private int subnetIpv6Prefix = 64;

    private IpAbuseScopeConfig ip = new IpAbuseScopeConfig();
    private IpAbuseScopeConfig subnet    = new IpAbuseScopeConfig();
    private IpAbuseScopeConfig userAgent = new IpAbuseScopeConfig();

}
