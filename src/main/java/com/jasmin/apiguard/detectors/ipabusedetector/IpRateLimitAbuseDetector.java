package com.jasmin.apiguard.detectors.ipabusedetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class IpRateLimitAbuseDetector implements Detector {

    private static final Logger log = LoggerFactory.getLogger(IpRateLimitAbuseDetector.class);

    // Redis namespaces
    private static final String NS_CREDITS = "rlc";       // request-credit state: rlc:<principal>
    private static final String NS_LOCK    = "ipa:lock";  // principal cool-off: ipa:lock:<principal>
    private static final String NS_STRIKE  = "ipa:strike";// strike counter:    ipa:strike:<principal>

    private final StringRedisTemplate redis;
    private final IpRateLimitAbuseProperties cfg;
    private final AntPathMatcher matcher = new AntPathMatcher();

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        final String principal = principalId(event);

        if (bypassed(principal, event)) {
            return Optional.empty();
        }

        // Cheap path: already in cool-off?
        if (isLocked(principal)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.IP_ABUSE),
                    List.of("RATE_LIMIT"),
                    "Principal in cool-off"
            ));
        }

        // Main decision: try to spend request credits
        CreditDecision dec = trySpendCredits(principal);

        if (!dec.allowed()) {
            int ttl = cfg.getCoolOffSeconds();
            if (cfg.isStrikeEscalationEnabled()) {
                ttl = Math.max(ttl, escalateLock(principal));
            }
            lockPrincipal(principal, Duration.ofSeconds(ttl));

            // Optional: structured log for tuning
            log.debug("IP rate-limit denial principal={} creditsAfter={} cps={} max={} cost={} lock={}s",
                    principal, String.format("%.3f", dec.creditsAfter()),
                    cfg.getCreditsPerSecond(), cfg.getMaxCredits(), cfg.getCreditsPerRequest(), ttl);

            String msg = String.format(
                    "Rate limited principal=%s (credits=%.3f, need=%d, max=%.1f, cps=%.2f/s)",
                    principal, dec.creditsAfter(), cfg.getCreditsPerRequest(),
                    cfg.getMaxCredits(), cfg.getCreditsPerSecond()
            );

            return Optional.of(new DetectionVerdict(
                    List.of(Constants.IP_ABUSE),
                    Arrays.asList("RATE_LIMIT", "BLOCK_IP"),
                    msg
            ));
        }

        return Optional.empty();
    }

    private record CreditDecision(boolean allowed, double creditsAfter) {}

    /**
     * Single request-credit pool per principal.
     * Hash fields: "c" (credits, double), "ts" (last update epoch ms, long).
     * Uses Redis WATCH/MULTI/EXEC (optimistic CAS) for concurrency safety.
     */
    private CreditDecision trySpendCredits(String principal) {
        final String key = creditsKey(principal);
        final long nowMs = Instant.now().toEpochMilli();

        // Small bounded retry for contention
        for (int attempt = 0; attempt < 5; attempt++) {
            Map<Object, Object> state = redis.opsForHash().entries(key);

            double max = cfg.getMaxCredits();
            double cps = cfg.getCreditsPerSecond();
            int cost   = cfg.getCreditsPerRequest();

            double credits = max; // default full
            long last = nowMs;    // default now

            if (!state.isEmpty()) {
                try {
                    credits = Double.parseDouble((String) state.getOrDefault("c", String.valueOf(max)));
                    last    = Long.parseLong((String) state.getOrDefault("ts", String.valueOf(nowMs)));
                } catch (NumberFormatException nfe) {
                    // Defensive: reset to sane defaults
                    credits = max;
                    last = nowMs;
                }
            }

            // Refill based on elapsed time
            double deltaSec = Math.max(0, (nowMs - last) / 1000.0);
            credits = Math.min(max, credits + deltaSec * cps);

            boolean allowed = credits >= cost;
            double newCredits = allowed ? (credits - cost) : credits;

            List<Object> tx = redis.execute(new SessionCallback<>() {
                @Override
                public List<Object> execute(org.springframework.data.redis.core.RedisOperations ops) throws DataAccessException {
                    ops.watch(key);
                    ops.multi();
                    ops.opsForHash().put(key, "c", Double.toString(newCredits));
                    ops.opsForHash().put(key, "ts", Long.toString(nowMs));
                    ops.expire(key, Duration.ofSeconds(idleTtlSeconds()));
                    return ops.exec();
                }
            });

            if (tx != null) {
                return new CreditDecision(allowed, newCredits);
            }
            // else CAS lost → retry
        }

        // In extreme contention or Redis hiccup, fail safe and deny
        log.warn("Credit CAS retries exhausted for principal={}", principal);
        return new CreditDecision(false, 0.0);
    }

    private long idleTtlSeconds() {
        var ttl = cfg.getIdleTtl();
        if (ttl != null && !ttl.isZero() && !ttl.isNegative()) {
            // clamp to [60s, 1d] to avoid immortal keys
            return Math.max(60, Math.min(86_400, ttl.toSeconds()));
        }
        // sensible default: full-refill time + 60s
        double seconds = (cfg.getMaxCredits() / Math.max(0.0001, cfg.getCreditsPerSecond())) + 60.0;
        return Math.max(60, Math.min(86_400, (long) Math.ceil(seconds)));
    }

    /* -------------------- Bypass & principal -------------------- */

    private boolean bypassed(String principal, SecurityEvent e) {
        if (cfg.getAllowlist().contains(e.getIp()) || cfg.getAllowlist().contains(principal)) return true;
        String path = DetectorUtils.nullSafe(e.getPath());
        for (String pat : cfg.getExcludePatterns()) {
            if (matcher.match(pat, path)) return true;
        }
        return false;
    }

    private String principalId(SecurityEvent e) {
        String ip = DetectorUtils.nullSafe(e.getIp());
        if (!cfg.isIncludeUserAgentInPrincipal()) return "ip:" + ip;
        String ua = DetectorUtils.nullSafe(e.getUserAgent());
        return "ipua:" + ip + ":" + ua.hashCode();
    }

    private boolean isLocked(String principal) {
        Long ttl = redis.getExpire(NS_LOCK + ":" + principal);
        return ttl > 0;
    }

    private void lockPrincipal(String principal, Duration ttl) {
        redis.opsForValue().set(NS_LOCK + ":" + principal, "1", ttl);
    }

    /**
     * Escalate lock duration based on strike count within a sliding TTL.
     * Returns the lock seconds to apply for this denial.
     */
    private int escalateLock(String principal) {
        String key = NS_STRIKE + ":" + principal;
        Long strikes = redis.opsForValue().increment(key);
        if (strikes != null && strikes == 1L) {
            redis.expire(key, Duration.ofSeconds(cfg.getStrikeWindowSeconds()));
        }
        if (strikes == null) return cfg.getCoolOffSeconds();
        if (strikes >= 3) return cfg.getStrike3LockSeconds();
        if (strikes == 2) return cfg.getStrike2LockSeconds();
        return cfg.getStrike1LockSeconds();
    }

    private String creditsKey(String principal) {
        return NS_CREDITS + ":" + principal;
    }
}