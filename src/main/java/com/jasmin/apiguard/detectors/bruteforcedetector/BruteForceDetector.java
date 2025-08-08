package com.jasmin.apiguard.detectors.bruteforcedetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
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
public class BruteForceDetector implements Detector {

    private final StringRedisTemplate redis;
    private final BruteForceProperties cfg;

    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");
    private static final String NS_COUNTER = "bf";       // counter namespace
    private static final String NS_LOCK = "bf:lock";  // lock namespace

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (!isLoginAttempt(event) || isKnownSuccess(event)) {
            return Optional.empty();
        }

        final String username = normalizeUser(nullSafe(event.getUsername()));
        final String ip = nullSafe(event.getIp());
        final long epochMinute = toEpochMinute(event);

        final String userId = username;
        final String ipId = ip;
        final String userIpId = username + ":" + ip;

        // 1) Fast-path: if any lock active, block immediately (no increments)
        Map<BruteForceScope, String> lockKeys = Map.of(
                BruteForceScope.USERNAME, lockKey(BruteForceScope.USERNAME, userId),
                BruteForceScope.IP, lockKey(BruteForceScope.IP, ipId),
                BruteForceScope.USER_IP, lockKey(BruteForceScope.USER_IP, userIpId)
        );

        if (anyActiveLock(lockKeys.values())) {
            return Optional.of(verdictLocked("Potential Brute-force attack active"));
        }

        // 2) Increment current bucket (per scope) and set TTL
        String bucketId = formatBucketId(epochMinute, cfg.getBucketMinutes());
        Map<BruteForceScope, String> bucketKeys = Map.of(
                BruteForceScope.USERNAME, bucketKey(BruteForceScope.USERNAME, userId, bucketId),
                BruteForceScope.IP, bucketKey(BruteForceScope.IP, ipId, bucketId),
                BruteForceScope.USER_IP, bucketKey(BruteForceScope.USER_IP, userIpId, bucketId)
        );
        incrementBuckets(bucketKeys.values(), Duration.ofMinutes(cfg.getExpiryMinutes()));

        // 3) Sum sliding window across last N buckets
        int bucketsToSum = Math.max(1, cfg.getWindowMinutes() / cfg.getBucketMinutes());
        Map<BruteForceScope, Long> sums = Map.of(
                BruteForceScope.USERNAME, sumBuckets(keysForWindow(BruteForceScope.USERNAME, userId, epochMinute, bucketsToSum)),
                BruteForceScope.IP, sumBuckets(keysForWindow(BruteForceScope.IP, ipId, epochMinute, bucketsToSum)),
                BruteForceScope.USER_IP, sumBuckets(keysForWindow(BruteForceScope.USER_IP, userIpId, epochMinute, bucketsToSum))
        );

        // 4) Check thresholds and set appropriate locks
        boolean userTrip = sums.get(BruteForceScope.USERNAME) > cfg.getThreshold().getUsername();
        boolean ipTrip = sums.get(BruteForceScope.IP) > cfg.getThreshold().getIp();
        boolean userIpTrip = sums.get(BruteForceScope.USER_IP) > cfg.getThreshold().getUserIp();

        if (userTrip || ipTrip || userIpTrip) {
            applyLocks(lockKeys, userTrip, ipTrip, userIpTrip, Duration.ofSeconds(cfg.getCoolOffSeconds()));

            String msg = String.format(
                    "Multiple failed logins (u=%d/%d, ip=%d/%d, uip=%d/%d) within %d-minute window",
                    sums.get(BruteForceScope.USERNAME), cfg.getThreshold().getUsername(),
                    sums.get(BruteForceScope.IP), cfg.getThreshold().getIp(),
                    sums.get(BruteForceScope.USER_IP), cfg.getThreshold().getUserIp(),
                    cfg.getWindowMinutes()
            );
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.BRUTE_FORCE_ATTACK),
                    Arrays.asList("LOCK_ACCOUNT", "BLOCK_IP", "RETRY_LATER"),
                    msg
            ));
        }

        return Optional.empty();
    }

    /**
     * Determines if the event represents a known successful login.
     * Currently always returns false (treats all login attempts as failures),
     * but can be wired to check event status/flags.
     */
    private boolean isKnownSuccess(SecurityEvent e) {
        // e.g., return Boolean.TRUE.equals(e.getSuccess()) or "SUCCESS".equalsIgnoreCase(e.getStatus());
        return false;
    }

    /**
     * Normalizes a username for consistent storage and comparison.
     * Converts to lower-case using a fixed locale.
     */
    private static String normalizeUser(String u) {
        return u.toLowerCase(Locale.ROOT);
    }

    /**
     * Returns a non-null, non-blank string.
     * If the input is null or blank, returns "unknown".
     */
    private static String nullSafe(String s) {
        return (s == null || s.isBlank()) ? "unknown" : s;
    }

    /**
     * Converts the event's timestamp to epoch minutes (UTC).
     * Useful for aligning into time buckets.
     */
    private static long toEpochMinute(SecurityEvent e) {
        return e.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond() / 60;
    }

    /**
     * Formats a bucket ID string for the given epoch minute and bucket size in minutes.
     * Aligns the minute to the nearest bucket boundary and formats as yyyyMMddHHmm.
     */
    private static String formatBucketId(long epochMinute, int bucketMinutes) {
        long aligned = (epochMinute / bucketMinutes) * bucketMinutes;
        return LocalDateTime.ofEpochSecond(aligned * 60, 0, ZoneOffset.UTC).format(BUCKET_FMT);
    }

    /**
     * Builds the Redis key for a brute-force counter bucket.
     * Format: bf:<scope>:<id>:<bucketId>
     */
    private static String bucketKey(BruteForceScope scope, String id, String bucketId) {
        return NS_COUNTER + ":" + scope.id + ":" + id + ":" + bucketId;
    }

    /**
     * Builds the Redis key for a brute-force lock for a specific scope and id.
     * Format: bf:lock:<scope>:<id>
     */
    private static String lockKey(BruteForceScope scope, String id) {
        return NS_LOCK + ":" + scope.id + ":" + id;
    }

    /**
     * Checks if any of the provided Redis lock keys are currently active (TTL > 0).
     * Returns true as soon as one active lock is found.
     */
    private boolean anyActiveLock(Collection<String> keys) {
        for (String k : keys) {
            Long ttlSec = redis.getExpire(k); // seconds
            if (ttlSec > 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Increments all provided Redis counter keys and sets their expiration to the given TTL.
     * This ensures buckets don't grow indefinitely in Redis.
     */
    private void incrementBuckets(Collection<String> keys, Duration ttl) {
        keys.forEach(k -> {
            redis.opsForValue().increment(k);
            redis.expire(k, ttl);
        });
    }

    /**
     * Generates a list of Redis bucket keys for a given scope/id over a sliding window.
     * Steps backwards in time for the specified number of buckets.
     */
    private List<String> keysForWindow(BruteForceScope scope, String id, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> formatBucketId(epochMinute - (long) i * step, step))
                .map(bucketId -> bucketKey(scope, id, bucketId))
                .collect(Collectors.toList());
    }

    /**
     * Reads multiple Redis counter keys and returns the sum of their values.
     * Ignores null or non-numeric values.
     */
    private long sumBuckets(List<String> keys) {
        long sum = 0L;
        List<String> vals = redis.opsForValue().multiGet(keys);
        if (vals == null) return 0L;
        for (String v : vals) {
            if (v != null && !v.isEmpty()) {
                try {
                    sum += Long.parseLong(v);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return sum;
    }

    /**
     * Sets brute-force lock keys in Redis for any scopes that exceeded their thresholds.
     * Locks are given the specified TTL to block further attempts temporarily.
     */
    private void applyLocks(Map<BruteForceScope, String> lockKeys,
                            boolean userTrip, boolean ipTrip, boolean userIpTrip,
                            Duration ttl) {
        if (userTrip) redis.opsForValue().set(lockKeys.get(BruteForceScope.USERNAME), "1", ttl);
        if (ipTrip) redis.opsForValue().set(lockKeys.get(BruteForceScope.IP), "1", ttl);
        if (userIpTrip) redis.opsForValue().set(lockKeys.get(BruteForceScope.USER_IP), "1", ttl);
    }

    /**
     * Creates a detection verdict for an already-active brute-force lock,
     * with standard tags and actions.
     */
    private static DetectionVerdict verdictLocked(String reason) {
        return new DetectionVerdict(
                List.of(Constants.BRUTE_FORCE_ATTACK),
                Arrays.asList("LOCK_ACCOUNT", "BLOCK_IP", "RETRY_LATER"),
                reason
        );
    }

}
