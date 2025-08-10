package com.jasmin.apiguard.detectors.replaydetector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class ReplayAttackDetector implements Detector {

    // Redis namespaces (compact and explicit)
    private static final String NS_ENFORCE = "replay:seen";   // idempotency/enforcement keys
    private static final String NS_COUNT   = "replay:count";  // duplicate counters
    private static final String NS_LOCK    = "replay:lock";   // principal cool-off

    /** Maximum length a key can be before it is abbreviated. */
    private static final int MAX_KEY_LENGTH = 16;

    /** Number of characters to keep from the start and end when abbreviating. */
    private static final int KEY_PART_LENGTH = 8;

    /** The string used to indicate that part of the key has been omitted. */
    private static final String ELLIPSIS = "…";

    private final StringRedisTemplate redis;
    private final ReplayProperties cfg;

    // Reuse a single ObjectMapper for JSON canonicalization
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        // Only protect configured methods (keep GET/HEAD free unless you explicitly opt-in)
        if (!isProtectedMethod(event.getMethod())) {
            return Optional.empty();
        }

        // Principal used only for mitigation (not part of equality)
        final String principal = principalId(event);

        // Pre-lock short-circuit: during cool-off we don't spend more Redis ops
        if (isLocked(principal)) {
            // 409 or 429 mapping is up to your gateway; we just provide the verdict.
            return Optional.of(verdict("Replay abuse lock active", List.of("REJECT_REQUEST")));
        }

        // Build "operation shape" and final request identity
        final String opShape = operationShape(event);
        final String requestIdentity = explicitIdKey(event)
                .map(id -> DetectorUtils.sha256Hex(id + "|" + opShape))  // bind ID to operation to prevent cross-endpoint reuse
                .orElseGet(() -> DetectorUtils.sha256Hex(opShape));

        // Idempotency enforcement: first seen wins within window
        final String enforceKey = NS_ENFORCE + ":" + requestIdentity;
        Boolean firstSeen = redis.opsForValue().setIfAbsent(
                enforceKey, "1", Duration.ofMillis(cfg.getWindowMillis())
        );
        if (Boolean.TRUE.equals(firstSeen)) {
            // First occurrence in the window → allow through
            return Optional.empty();
        }

        // Duplicate inside window → track and possibly cool off abusive principals
        final String cntKey = NS_COUNT + ":" + principal + ":" + requestIdentity;
        Long n = redis.opsForValue().increment(cntKey);
        if (n != null && n == 1L) {
            redis.expire(cntKey, Duration.ofMillis(cfg.getWindowMillis()));
        }

        if (n != null && n >= cfg.getAbuseThreshold()) {
            lockPrincipal(principal, Duration.ofSeconds(cfg.getCoolOffSeconds()));
            // Bucket this IP for broader mitigation decisions in your pipeline
            if (log.isWarnEnabled()) {
                log.warn("Replay abuse: principal={} identity={} duplicates={} windowMs={}",
                        principal, shortKey(requestIdentity), n, cfg.getWindowMillis());
            }

            return Optional.of(verdict(
                    String.format("Replay attack: %s repeated %d times within %d ms",
                            shortKey(requestIdentity), n, cfg.getWindowMillis()
                    ),
                    List.of("REJECT_REQUEST")
            ));
        }

        // Duplicate but under threshold: still a replay
        return Optional.of(verdict("Duplicate request within idempotency window", List.of("REJECT_REQUEST")));
    }

    /** True if HTTP method is protected (mutating methods by default). */
    private boolean isProtectedMethod(String method) {
        return method != null && cfg.getProtectedMethods().contains(method.toUpperCase(Locale.ROOT));
    }

    /** Principal to lock on abuse: IP or IP+UA (UA hashed) to reduce big-NAT false positives. */
    private String principalId(SecurityEvent e) {
        String ip = DetectorUtils.firstNonEmpty(e.getIp(), e.getRemoteAddr(), "unknown");
        if (!cfg.isIncludeUserAgentInPrincipal()) return "ip:" + ip;
        String ua = headerFirst(e.getHeaders(), "User-Agent");
        return "ipua:" + ip + ":" + ua.hashCode();
    }

    /** Builds a stable description of the operation: METHOD + canonical PATH + canonical QUERY + BODY hash. */
    private String operationShape(SecurityEvent e) {
        String method = DetectorUtils.getValueOrEmptyString(e.getMethod()).toUpperCase(Locale.ROOT);
        String path   = canonicalPath(DetectorUtils.getValueOrEmptyString(e.getPath()));
        String query  = canonicalQuery(e.getQueryParams(), cfg.getIgnoredQueryParams());
        String bodyH  = bodyHash(e.getContentType(), e.getBody());
        return "m=" + method + "&p=" + path + "&q=" + query + "&b=" + bodyH;
    }

    /** Try explicit idempotency/Correlation keys from multi-value headers (case-insensitive). */
    private Optional<String> explicitIdKey(SecurityEvent e) {
        Map<String, List<String>> headers = e.getHeaders();
        if (headers != null && !headers.isEmpty()) {
            for (String wanted : cfg.getIdempotencyHeaderNames()) {
                String v = headerFirst(headers, wanted);
                if (!v.isBlank()) return Optional.of("id:" + v);
            }
        }
        if (e.getCorrelationId() != null && !e.getCorrelationId().isBlank()) {
            return Optional.of("cid:" + e.getCorrelationId());
        }
        return Optional.empty();
    }

    /** Returns the first value for a header (case-insensitive) from Map<String,List<String>>. Returns "" if none. */
    private String headerFirst(Map<String, List<String>> headers, String name) {
        if (headers == null || name == null) return "";
        for (Map.Entry<String, List<String>> en : headers.entrySet()) {
            if (en.getKey() != null && en.getKey().equalsIgnoreCase(name)) {
                List<String> vals = en.getValue();
                if (vals != null && !vals.isEmpty()) {
                    String v = vals.getFirst();
                    return v == null ? "" : v;
                }
                return "";
            }
        }
        return "";
    }

    /** Canonicalize path: collapse duplicate slashes and drop trailing slash (except root). */
    private String canonicalPath(String p) {
        String s = p.replaceAll("/{2,}", "/");
        if (s.endsWith("/") && s.length() > 1) s = s.substring(0, s.length() - 1);
        return s;
    }

    /** Canonicalize query from Map<String,List<String>>: sort keys & values; drop ignored params. */
    private String canonicalQuery(Map<String, List<String>> qp, Set<String> ignore) {
        if (qp == null || qp.isEmpty()) return "";
        return qp.entrySet().stream()
                .filter(en -> en.getKey() != null && (ignore == null || !ignore.contains(en.getKey())))
                .sorted(Map.Entry.comparingByKey())
                .map(en -> {
                    List<String> vals = en.getValue() == null ? List.of() : en.getValue();
                    List<String> sorted = new ArrayList<>(vals);
                    sorted.sort(Comparator.nullsFirst(String::compareTo));
                    if (sorted.isEmpty()) return en.getKey();
                    return en.getKey() + "=" + String.join(",", sorted); // deterministic multi-value join
                })
                .reduce((a,b) -> a + "&" + b)
                .orElse("");
    }

    /**
     * Computes a stable body hash.
     * - Caps bytes to maxBodyBytes to bound cost.
     * - For application/json, canonicalizes with Jackson (sorted keys, no whitespace).
     * - Falls back to raw slice hashing when JSON parsing fails.
     */
    private String bodyHash(String contentType, byte[] body) {
        byte[] raw = (body == null) ? new byte[0] : body;
        if (raw.length == 0) return "nobody";
        int len = Math.min(raw.length, cfg.getMaxBodyBytes());
        String slice = new String(raw, 0, len, StandardCharsets.UTF_8);

        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (cfg.isCanonicalizeJson() && ct.contains("application/json")) {
            try {
                return DetectorUtils.sha256Hex("json:" + mapper.writeValueAsString(mapper.readTree(slice)));
            } catch (Exception ex) {
                // fall through to raw hashing
            }
        }
        return DetectorUtils.sha256Hex("raw:" + slice);
    }

    /** True if the principal has an active cool-off lock. */
    private boolean isLocked(String principal) {
        Long ttl = redis.getExpire(NS_LOCK + ":" + principal);
        return ttl > 0;
    }

    /** Locks the principal for the given TTL to short-circuit abusive replays. */
    private void lockPrincipal(String principal, Duration ttl) {
        redis.opsForValue().set(NS_LOCK + ":" + principal, "1", ttl);
    }

    /**
     * Utility for shortening long keys for logging, debugging, or display purposes.
     * <p>
     * If the input string length is less than or equal to {@link #MAX_KEY_LENGTH}, the string is returned unchanged.
     * Otherwise, the string is abbreviated by keeping the first {@link #KEY_PART_LENGTH} characters
     * and the last {@link #KEY_PART_LENGTH} characters, separated by an {@link #ELLIPSIS}.
     * <p>
     * Example:
     * <pre>
     * shortKey("12345678901234567890")  → "12345678…34567890"
     * shortKey("short")                → "short"
     * </pre>
     */
    private static String shortKey(String key) {
        if (key == null) return null;
        return (key.length() <= MAX_KEY_LENGTH)
                ? key
                : key.substring(0, KEY_PART_LENGTH) + ELLIPSIS + key.substring(key.length() - KEY_PART_LENGTH);
    }

    /** Standard detection verdict for replay decisions. */
    private static DetectionVerdict verdict(String msg, List<String> actions) {
        return new DetectionVerdict(
                List.of(Constants.REPLAY_ATTACK),
                actions,
                msg
        );
    }
}
