package com.jasmin.apiguard.detectors.enumerationattackdetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import com.jasmin.apiguard.services.KeyManager;
import com.jasmin.apiguard.services.ThreatBucketService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
public class EnumerationAttackDetector implements Detector {

    private final StringRedisTemplate redis;
    private final ThreatBucketService threatBucketService;
    private final EnumerationProperties cfg;

    private static final String NS_HLL  = "enum:hll";   // per-bucket HLL namespace
    private static final String NS_LOCK = "enum:lock";  // cool-off lock namespace
    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (!isLoginAttempt(event)) {
            return Optional.empty();
        }

        String username = normalizedUsername(event.getUsername());
        if (username == null) {
            return Optional.empty(); // nothing to count
        }

        String principal = principalKeyPart(event);
        long epochMinute = toEpochMinute(event);

        // 1) Fast path: is principal locked?
        String lockKey = lockKey(principal);
        if (isLocked(lockKey)) {
            return Optional.of(blockVerdict("Potential Enumeration attack active"));
        }

        // 2) Record username in current bucket’s HLL
        String bucketId = formatBucketId(epochMinute, cfg.getBucketMinutes());
        String hllKey = hllKey(principal, bucketId);
        redis.opsForHyperLogLog().add(hllKey, username);
        redis.expire(hllKey, Duration.ofMinutes(cfg.getExpiryMinutes()));

        // 3) Count distinct usernames across sliding window using PFCOUNT over keys
        int bucketsToSum = Math.max(1, cfg.getWindowMinutes() / cfg.getBucketMinutes());
        List<String> windowKeys = windowHllKeys(principal, epochMinute, bucketsToSum);
        Long uniqueCount = redis.opsForHyperLogLog().size(windowKeys.toArray(new String[0]));
        long count = uniqueCount == null ? 0L : uniqueCount;

        // 4) Threshold + mitigation
        if (count >= cfg.getThreshold()) {
            // Cool-off this principal
            redis.opsForValue().set(lockKey, "1", Duration.ofSeconds(cfg.getCoolOffSeconds()));
            // Add to your malicious bucket
            threatBucketService.addToBucket(KeyManager.MALICIOUS_IP_BUCKET, event.getIp());

            String msg = String.format(
                    "Enumeration suspected: %d unique usernames from principal=%s within %d-minute window",
                    count, principal, cfg.getWindowMinutes()
            );
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.ENUMERATION_ATTACK),
                    List.of("BLOCK_IP"),
                    msg
            ));
        }

        return Optional.empty();
    }

    // ======== Helpers (with clear, short JavaDocs) ========

    /**
     * Normalizes the username for stable uniqueness counting.
     * Lowercases; returns null if missing/blank.
     */
    private String normalizedUsername(String username) {
        if (username == null || username.isBlank()) return null;
        return username.toLowerCase(Locale.ROOT);
    }

    /**
     * Builds the principal identifier used for keys.
     * By default IP or IP+UserAgent (to reduce NAT false positives).
     * Format: "ip:<ip>" or "ipua:<ip>:<uaHash>"
     */
    private String principalKeyPart(SecurityEvent event) {
        String ip = safe(event.getIp());
        if (!cfg.isIncludeUserAgentInPrincipal()) {
            return "ip:" + ip;
        }
        String ua = safe(event.getUserAgent());
        int uaHash = ua.hashCode(); // short, non-PII identifier
        return "ipua:" + ip + ":" + uaHash;
    }

    /**
     * Converts the event timestamp to epoch minutes (UTC).
     * Used to align into time buckets.
     */
    private long toEpochMinute(SecurityEvent event) {
        return event.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond() / 60;
    }

    /**
     * Formats a bucket ID by aligning the epoch minute to the bucket size and
     * rendering as yyyyMMddHHmm.
     */
    private String formatBucketId(long epochMinute, int bucketMinutes) {
        long aligned = (epochMinute / bucketMinutes) * bucketMinutes;
        return LocalDateTime.ofEpochSecond(aligned * 60, 0, ZoneOffset.UTC).format(BUCKET_FMT);
    }

    /**
     * Returns the Redis key for the per-bucket HyperLogLog:
     * enum:hll:<principal>:<bucketId>
     */
    private String hllKey(String principal, String bucketId) {
        return NS_HLL + ":" + principal + ":" + bucketId;
    }

    /**
     * Returns the Redis key for the principal’s enumeration cool-off lock:
     * enum:lock:<principal>
     */
    private String lockKey(String principal) {
        return NS_LOCK + ":" + principal;
    }

    /**
     * True if the principal has an active cool-off lock (TTL > 0).
     * Short-circuits heavy work during ongoing attacks.
     */
    private boolean isLocked(String lockKey) {
        Long ttlSec = redis.getExpire(lockKey);
        return ttlSec != null && ttlSec > 0;
    }

    /**
     * Builds the list of HLL keys to query for the sliding window.
     * Walks backwards from the current bucket across N buckets.
     */
    private List<String> windowHllKeys(String principal, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> formatBucketId(epochMinute - (long) i * step, step))
                .map(bucketId -> hllKey(principal, bucketId))
                .collect(Collectors.toList());
    }

    /**
     * Returns a non-null, non-empty string; substitutes "unknown" when missing.
     */
    private static String safe(String s) {
        return (s == null || s.isBlank()) ? "unknown" : s;
    }

    /**
     * Creates a standard detection verdict for active enumeration locks.
     */
    private static DetectionVerdict blockVerdict(String reason) {
        return new DetectionVerdict(
                List.of(Constants.ENUMERATION_ATTACK),
                List.of("BLOCK_IP"),
                reason
        );
    }
}
