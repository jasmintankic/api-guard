package com.jasmin.apiguard.detectors.ipabusedetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import com.jasmin.apiguard.services.KeyManager;
import com.jasmin.apiguard.services.ThreatBucketService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
public class IpAbuseDetector implements Detector {

    private static final String NS_CTR  = "ipa:ctr";   // counters per bucket
    private static final String NS_LOCK = "ipa:lock";  // principal cool-off lock
    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    private final StringRedisTemplate redis;
    private final ThreatBucketService threatBucketService;
    private final IpAbuseProperties cfg;
    private final AntPathMatcher matcher = new AntPathMatcher();

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        final String principal = principalId(event);
        if (bypassed(principal, event)) return Optional.empty();

        // Fast path: active lock?
        if (isLocked(principal)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.IP_ABUSE),
                    List.of("RATE_LIMIT"), // keep cheap during lock; your gateway can 429 with Retry-After
                    "IP principal in cool-off"
            ));
        }

        // Determine weight for this endpoint/method
        int weight = weightFor(event.getPath());

        // Increment current bucket
        long epochMinute = event.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond() / 60;
        String bucketId = formatBucketId(epochMinute, cfg.getBucketMinutes());
        String ctrKey = counterKey(principal, bucketId);
        Long now = redis.opsForValue().increment(ctrKey, weight);
        redis.expire(ctrKey, Duration.ofMinutes(cfg.getExpiryMinutes()));

        // Aggregate sliding window
        int bucketsToSum = Math.max(1, cfg.getWindowMinutes() / cfg.getBucketMinutes());
        long sum = sumBuckets(windowCounterKeys(principal, epochMinute, bucketsToSum));

        if (sum > cfg.getThreshold()) {
            // Lock principal briefly and flag IP
            lockPrincipal(principal, Duration.ofSeconds(cfg.getCoolOffSeconds()));
            threatBucketService.addToBucket(KeyManager.MALICIOUS_IP_BUCKET, event.getIp());

            String msg = String.format(
                    "High request volume from principal=%s: %d>%d in %d-min window",
                    principal, sum, cfg.getThreshold(), cfg.getWindowMinutes()
            );
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.IP_ABUSE),
                    Arrays.asList("RATE_LIMIT", "BLOCK_IP"), // you can choose which your pipeline enforces
                    msg
            ));
        }

        return Optional.empty();
    }

    /* ================= helpers ================= */

    private boolean bypassed(String principal, SecurityEvent e) {
        // Allowlist
        if (cfg.getAllowlist().contains(e.getIp()) || cfg.getAllowlist().contains(principal)) return true;
        // Exclusions by path
        String ep = safe(e.getPath());
        for (String pat : cfg.getExcludePatterns()) {
            if (matcher.match(pat, ep)) return true;
        }
        return false;
    }

    private String principalId(SecurityEvent e) {
        String ip = safe(e.getIp());
        if (!cfg.isIncludeUserAgentInPrincipal()) return "ip:" + ip;
        String ua = safe(e.getUserAgent());
        return "ipua:" + ip + ":" + ua.hashCode();
    }

    private int weightFor(String endpoint) {
        String ep = safe(endpoint);
        for (Map.Entry<String,Integer> en : cfg.getWeightedPatterns().entrySet()) {
            if (matcher.match(en.getKey(), ep)) return Math.max(1, en.getValue());
        }
        return 1; // default weight
    }

    private boolean isLocked(String principal) {
        Long ttl = redis.getExpire(NS_LOCK + ":" + principal);
        return ttl != null && ttl > 0;
    }

    private void lockPrincipal(String principal, Duration ttl) {
        redis.opsForValue().set(NS_LOCK + ":" + principal, "1", ttl);
    }

    private static String formatBucketId(long epochMinute, int bucketMinutes) {
        long aligned = (epochMinute / bucketMinutes) * bucketMinutes;
        return LocalDateTime.ofEpochSecond(aligned * 60, 0, ZoneOffset.UTC).format(BUCKET_FMT);
    }

    private String counterKey(String principal, String bucketId) {
        return NS_CTR + ":" + principal + ":" + bucketId;
    }

    private List<String> windowCounterKeys(String principal, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> formatBucketId(epochMinute - (long) i * step, step))
                .map(bid -> counterKey(principal, bid))
                .collect(Collectors.toList());
    }

    private long sumBuckets(List<String> keys) {
        long sum = 0L;
        List<String> vals = redis.opsForValue().multiGet(keys);
        if (vals == null) return 0L;
        for (String v : vals) {
            if (v != null && !v.isEmpty()) {
                try { sum += Long.parseLong(v); } catch (NumberFormatException ignored) {}
            }
        }
        return sum;
    }

    private static String safe(String s) {
        return (s == null || s.isBlank()) ? "unknown" : s;
    }
}