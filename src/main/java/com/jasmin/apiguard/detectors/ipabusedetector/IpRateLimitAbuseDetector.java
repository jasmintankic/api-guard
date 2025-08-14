package com.jasmin.apiguard.detectors.ipabusedetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.time.Duration;
import java.util.*;

@Service
@RequiredArgsConstructor
public class IpRateLimitAbuseDetector implements Detector {

    private static final String NS_CREDITS = "rlc";
    private static final String NS_LOCK = "ipa:lock";
    private static final String NS_STRIKE = "ipa:strike";

    private final StringRedisTemplate redis;
    private final IpRateLimitAbuseProperties cfg;
    private final AntPathMatcher matcher = new AntPathMatcher();

    private static final RedisScript<List<Object>> LUA_SCRIPT = DetectorUtils.loadLuaScript("lua/ip_rate_limit.lua");

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (!cfg.isEnabled()) {
            return Optional.empty();
        }

        final String principal = buildPrincipal(event);

        if (isBypassed(principal, event)) {
            return Optional.empty();
        }

        // 1) Subnet scope
        if (cfg.isSubnetRateLimitEnabled()) {
            final String subnetId = buildSubnetId(DetectorUtils.nullSafe(event.getIp()));
            var v = enforceScope(
                    subnetId,
                    cfg.getSubnet(),
                    false,
                    "Subnet in cool-off",
                    "Subnet over limit",
                    List.of("RATE_LIMIT_SUBNET"),
                    List.of(Constants.SUBNET_ABUSE)
            );

            if (v.isPresent()) {
                return v;
            }
        }

        // 2) User-Agent scope
        if (cfg.isUserAgentRateLimitEnabled()) {
            final String uaId = buildUserAgentKey(event.getUserAgent());
            var v = enforceScope(
                    uaId,
                    cfg.getUserAgent(),
                   false,
                    "User-Agent in cool-off",
                    "User-Agent over limit",
                    List.of("RATE_LIMIT_UA"),
                    List.of(Constants.IP_ABUSE_USER_AGENT)
            );
            if (v.isPresent()) return v;
        }

        // 3) ip scope (supports strike escalation)
        return enforceScope(
                principal,
                cfg.getIp(),
                cfg.isStrikeEscalationEnabled(),
                "Principal in cool-off",
                "Rate limited",
                List.of("RATE_LIMIT", "BLOCK_IP"),
                List.of(Constants.IP_ABUSE)
        );
    }

    private Optional<DetectionVerdict> enforceScope(
            String subjectId,
            IpAbuseScopeConfig sc,
            boolean escalationEnabled,
            String lockedReason,
            String overLimitReason,
            List<String> actionsOnDeny,
            List<String> tags
    ) {
        // Already locked?
        if (isLocked(subjectId)) {
            return verdict(tags, actionsOnDeny.size() == 1 ? List.of(actionsOnDeny.getFirst()) : actionsOnDeny, lockedReason + " - " + subjectId);
        }

        // Try to spend a token
        boolean allowed = spend(subjectId, sc);
        if (allowed) {
            return Optional.empty();
        }

        // Not allowed -> compute lock TTL (with optional strike escalation on principal scope)
        int ttl = cfg.getCoolOffSeconds();
        if (escalationEnabled) {
            ttl = Math.max(ttl, escalateLockSeconds(subjectId));
        }
        lock(subjectId, ttl);

        return verdict(tags, actionsOnDeny, overLimitReason + ": " + subjectId);
    }

    private boolean spend(String subjectId, IpAbuseScopeConfig sc) {
        final int idleTtl = computeIdleTtlSeconds(sc);
        final List<String> keys = List.of(creditsKey(subjectId));
        final List<String> args = List.of(
                String.valueOf(sc.getMaxCredits()),
                String.valueOf(sc.getCreditsPerSecond()),
                String.valueOf(sc.getCreditsPerRequest()),
                String.valueOf(idleTtl)
        );

        List<Object> result = redis.execute(LUA_SCRIPT, keys, args.toArray());
        if (result == null || result.size() < 2) {
            return cfg.isFailOpenOnRedisError(); // policy: fail-open or fail-closed on Redis issues
        }
        // first item is 1/0
        return "1".equals(result.getFirst().toString()) || "1.0".equals(result.getFirst().toString());
    }

    private int computeIdleTtlSeconds(IpAbuseScopeConfig sc) {
        final var set = sc.getIdleTtl();
        if (set != null && !set.isZero() && !set.isNegative()) {
            return (int) clamp(set.toSeconds(), 60, 86_400);
        }
        double seconds = (sc.getMaxCredits() / Math.max(0.0001, sc.getCreditsPerSecond())) + 60.0;
        return (int) clamp(Math.ceil(seconds), 60, 86_400);
    }

    private void lock(String subject, int seconds) {
        int ttl = withJitter(seconds, cfg.getLockJitterPercent());
        redis.opsForValue().set(lockKey(subject), "1", Duration.ofSeconds(ttl));
    }

    private boolean isLocked(String subject) {
        Long ttl = redis.getExpire(lockKey(subject));
        return ttl != null && ttl > 0;
    }

    private int escalateLockSeconds(String subject) {
        String key = NS_STRIKE + ":" + subject;
        Long strikes = redis.opsForValue().increment(key);

        if (strikes != null && strikes == 1L) {
            redis.expire(key, Duration.ofSeconds(cfg.getStrikeWindowSeconds()));
        }

        if (strikes == null) {
            return cfg.getCoolOffSeconds();
        }

        if (strikes >= 3) {
            return cfg.getStrike3LockSeconds();
        }

        if (strikes == 2) {
            return cfg.getStrike2LockSeconds();
        }

        return cfg.getStrike1LockSeconds();
    }

    private String buildPrincipal(SecurityEvent e) {
        String ip = DetectorUtils.nullSafe(e.getIp());
        if (!cfg.isIncludeUserAgentInPrincipal()) return "ip:" + ip;
        return "ipua:" + ip + ":" + normalizedUaHash(e.getUserAgent());
    }

    private String buildUserAgentKey(String ua) {
        return "ua:" + normalizedUaHash(ua);
    }

    private String normalizedUaHash(String ua) {
        String norm = DetectorUtils.nullSafe(ua).trim()
                .toLowerCase(Locale.ROOT)
                .replaceAll("\\s+", " ");
        return Integer.toString(norm.hashCode());
    }

    private String buildSubnetId(String ip) {
        if (ip == null) return "subnet:unknown";
        if (ip.contains(":")) {
            // IPv6
            int prefix = Math.min(Math.max(cfg.getSubnetIpv6Prefix(), 16), 128);
            int hextets = Math.max(1, prefix / 16);
            String[] parts = ip.split(":", -1);
            StringBuilder sb = new StringBuilder("subnet6:");
            for (int i = 0; i < hextets && i < parts.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(parts[i].isEmpty() ? "0" : parts[i]);
            }
            sb.append("::/").append(prefix);
            return sb.toString();
        } else {
            // IPv4
            int prefix = Math.min(Math.max(cfg.getSubnetIpv4Prefix(), 8), 32);
            String[] parts = ip.split("\\.");
            if (parts.length != 4) return "subnet:unknown";
            int octets = Math.max(1, prefix / 8);
            StringBuilder sb = new StringBuilder("subnet4:");
            for (int i = 0; i < Math.min(octets, 3); i++) {
                if (i > 0) sb.append('.');
                sb.append(parts[i]);
            }
            if (octets >= 3) sb.append(".0");
            sb.append("/").append(prefix);
            return sb.toString();
        }
    }

    private boolean isBypassed(String principal, SecurityEvent e) {
        if (!cfg.isEnabled()) {
            return true;
        }
        if (cfg.getAllowlist().contains(DetectorUtils.nullSafe(e.getIp()))) return true;
        if (cfg.getAllowlist().contains(principal)) return true;
        String path = DetectorUtils.nullSafe(e.getPath());
        for (String pat : cfg.getExcludePatterns()) {
            if (matcher.match(pat, path)) return true;
        }
        return false;
    }

    private String creditsKey(String subject) {
        return NS_CREDITS + ":" + subject;
    }

    private String lockKey(String subject) {
        return NS_LOCK + ":" + subject;
    }

    private Optional<DetectionVerdict> verdict(List<String> tags, List<String> actions, String message) {
        return Optional.of(new DetectionVerdict(tags, actions, message));
    }

    private static double clamp(double v, double lo, double hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private static int withJitter(int seconds, double fraction) {
        double f = Math.max(0.0, Math.min(1.0, fraction));
        int jitter = (int) Math.floor(seconds * (Math.random() * f));
        return seconds + Math.max(0, jitter);
    }
}