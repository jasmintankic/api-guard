package com.jasmin.apiguard.detectors.enumerationattackdetector;


import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
public class EnumerationAttackDetector implements Detector {

    private final StringRedisTemplate redis;
    private final EnumerationProperties cfg;

    // Namespaces
    private static final String NS_HLL           = "enum:hll";           // per-principal distinct usernames (HLL, bucketed)
    private static final String NS_LOCK          = "enum:lock";          // principal cool-off lock
    private static final String NS_USERIPS_HLL   = "enum:userips:hll";   // per-username distinct IPs (HLL, bucketed)
    private static final String NS_IPRATE_Z      = "enum:iprate:z";      // per-principal request timestamps (ZSET)

    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (!DetectorUtils.isLoginAttempt(event)) {
            return Optional.empty();
        }

        String username = DetectorUtils.normalizeValue(event.getUsername());
        if (username == null) {
            return Optional.empty(); // nothing to count
        }

        String principal = principalKeyPart(event);
        long epochMinute = DetectorUtils.toEpochMinute(event.getTimestamp());
        String lockKey = lockKey(principal);

        // 1) Fast path: locked principals are immediately blocked
        if (isLocked(lockKey)) {
            return Optional.of(blockVerdict("Potential Enumeration attack active"));
        }

        // ==== Signal A: distinct usernames per principal (your original) ====
        String principalBucketId = DetectorUtils.formatBucketId(epochMinute, cfg.getBucketMinutes());
        String principalHllKey = hllKey(principal, principalBucketId);
        redis.opsForHyperLogLog().add(principalHllKey, username);
        // TTL should outlive the window by at least one bucket
        redis.expire(principalHllKey, Duration.ofMinutes(cfg.getExpiryMinutes()));

        int aBuckets = ceilDiv(cfg.getWindowMinutes(), cfg.getBucketMinutes());
        long distinctUsersFromPrincipal = redis.opsForHyperLogLog().size(
                windowHllKeys(principal, epochMinute, aBuckets).toArray(new String[0])
        );
        boolean principalEnum = distinctUsersFromPrincipal >= cfg.getThreshold();

        // ==== Signal B: distinct IPs per username (inverse view) ====
        String userIpsBucketId = principalBucketId; // same bucket size
        String userIpsKey = userIpsHllKey(username, userIpsBucketId);
        String ipForUser = DetectorUtils.nullSafe(event.getIp());
        redis.opsForHyperLogLog().add(userIpsKey, ipForUser);
        redis.expire(userIpsKey, Duration.ofMinutes(cfg.getUserIpsExpiryMinutes()));

        int bBuckets = ceilDiv(cfg.getUserIpsWindowMinutes(), cfg.getBucketMinutes());
        long distinctIpsForUser = redis.opsForHyperLogLog().size(
                userIpsWindowKeys(username, epochMinute, bBuckets).toArray(new String[0])
        );
        boolean usernameUnderSpray = distinctIpsForUser >= cfg.getUserIpsThreshold();

        // ==== Signal C: per-principal raw request rate (precise sliding window via ZSET) ====
        String zKey = ipRateKey(principal);
        long nowMs = System.currentTimeMillis();
        long cutoff = nowMs - (cfg.getIpRateWindowSeconds() * 1000L);

        // Add a mostly-unique member at 'nowMs' score to avoid collisions in the same millisecond
        String member = nowMs + ":" + UUID.randomUUID();
        redis.opsForZSet().add(zKey, member, nowMs);
        redis.opsForZSet().removeRangeByScore(zKey, 0, cutoff);
        Long ipReqs = redis.opsForZSet().zCard(zKey);
        redis.expire(zKey, Duration.ofSeconds(cfg.getIpRateWindowSeconds() + 5));

        boolean ipBursting = ipReqs != null && ipReqs >= cfg.getIpRateLimit();

        // ==== Decision & mitigation ====
        if (principalEnum || usernameUnderSpray || ipBursting) {
            int ttl = jitteredTtl(cfg.getCoolOffSeconds());
            redis.opsForValue().set(lockKey, "1", Duration.ofSeconds(ttl));

            // Build a concise message indicating which signals tripped
            List<String> reasons = new ArrayList<>();
            if (principalEnum) {
                reasons.add(String.format("A: %d unique usernames from principal=%s in %dm", distinctUsersFromPrincipal, principal, cfg.getWindowMinutes()));
            }
            if (usernameUnderSpray) {
                reasons.add(String.format("B: %d distinct IPs hitting username=%s in %dm", distinctIpsForUser, username, cfg.getUserIpsWindowMinutes()));
            }
            if (ipBursting) {
                reasons.add(String.format("C: %d requests from principal=%s in %ds", ipReqs, principal, cfg.getIpRateWindowSeconds()));
            }

            String msg = "Enumeration suspected (" + String.join("; ", reasons) + ")";
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.ENUMERATION_ATTACK),
                    List.of("BLOCK_IP"),
                    msg
            ));
        }

        return Optional.empty();
    }

    /** "ip:<ip>" or "ipua:<ip>:<uaHash>" depending on config. */
    private String principalKeyPart(SecurityEvent event) {
        String ip = DetectorUtils.nullSafe(event.getIp());
        if (!cfg.isIncludeUserAgentInPrincipal()) {
            return "ip:" + ip;
        }
        String ua = DetectorUtils.nullSafe(event.getUserAgent());
        int uaHash = ua.hashCode(); // short, non-PII identifier
        return "ipua:" + ip + ":" + uaHash;
    }

    /** enum:hll:<principal>:<bucketId> */
    private String hllKey(String principal, String bucketId) {
        return NS_HLL + ":" + principal + ":" + bucketId;
    }

    /** enum:userips:hll:<usernameLower>:<bucketId> */
    private String userIpsHllKey(String username, String bucketId) {
        return NS_USERIPS_HLL + ":" + username + ":" + bucketId;
    }

    /** enum:iprate:z:<principal> */
    private String ipRateKey(String principal) {
        return NS_IPRATE_Z + ":" + principal;
    }

    /** enum:lock:<principal> */
    private String lockKey(String principal) {
        return NS_LOCK + ":" + principal;
    }

    /** Active cool-off lock if TTL > 0 (we always set lock with a TTL). */
    private boolean isLocked(String lockKey) {
        Long ttlSec = redis.getExpire(lockKey);
        return ttlSec > 0;
    }

    /** Backwards list of principal HLL keys across N buckets (A-signal). */
    private List<String> windowHllKeys(String principal, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> DetectorUtils.formatBucketId(epochMinute - (long) i * step, step))
                .map(bucketId -> hllKey(principal, bucketId))
                .collect(Collectors.toList());
    }

    /** Backwards list of username->IPs HLL keys across N buckets (B-signal). */
    private List<String> userIpsWindowKeys(String username, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> DetectorUtils.formatBucketId(epochMinute - (long) i * step, step))
                .map(bucketId -> userIpsHllKey(username, bucketId))
                .collect(Collectors.toList());
    }

    /** Always ceil division for window/bucket → number of buckets. */
    private static int ceilDiv(int a, int b) {
        return (a + b - 1) / b;
    }

    /** Add a tiny jitter (0–10%) to avoid synchronized unlocks. */
    private static int jitteredTtl(int seconds) {
        int jitter = (int) Math.floor(seconds * (Math.random() * 0.10));
        return seconds + jitter;
    }

    /** Standard detection verdict for active locks. */
    private static DetectionVerdict blockVerdict(String reason) {
        return new DetectionVerdict(
                List.of(Constants.ENUMERATION_ATTACK),
                List.of("BLOCK_IP"),
                reason
        );
    }
}