package com.jasmin.apiguard.detectors.trafficanomalydetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
public class TrafficAnomalyDetector implements Detector {

    // per-endpoint minute buckets
    private static final String NS_CTR   = "bs:ep:ctr";     // bs:ep:ctr:<epKey>:<bucket> -> Long (requests in minute)
    private static final String NS_IPS   = "bs:ep:ips";     // bs:ep:ips:<epKey>:<bucket> -> Set<ip>

    // per-endpoint baseline stats + samples warm-up + minute-seen marker
    private static final String NS_MEAN  = "bs:ep:mean";    // bs:ep:mean:<epKey>  -> Double
    private static final String NS_VAR   = "bs:ep:var";     // bs:ep:var:<epKey>   -> Double
    private static final String NS_SAM   = "bs:ep:samples"; // bs:ep:samples:<epKey> -> Long (distinct minutes seen)
    private static final String NS_SEEN  = "bs:ep:seen";    // bs:ep:seen:<epKey>:<bucket> -> "1" (minute marker)

    // endpoint cool-off locks
    private static final String NS_LOCK  = "bs:ep:lock";    // bs:ep:lock:<epKey> -> "1" with TTL

    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    private final StringRedisTemplate redis;
    private final TrafficAnomalyProperties cfg;

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        final String path = DetectorUtils.nullSafe(event.getPath());
        if (excluded(path)) {
            return Optional.empty();
        }

        final String epKey = endpointKey(path);

        // Short-circuit if endpoint is in cool-off
        if (isLocked(epKey)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.TRAFFIC_SPIKE),
                    List.of("RATE_LIMIT_ENDPOINT", "CHALLENGE_ENDPOINT", "RETRY_LATER"),
                    "Endpoint baseline surge cool-off active"
            ));
        }

        // Current minute bucket & keys
        Instant ts = event.getTimestamp();
        long epochMinute = DetectorUtils.toEpochMinute(ts);
        String bucketId = DetectorUtils.formatBucketId(epochMinute, cfg.getBucketMinutes());
        Duration ttl = Duration.ofMinutes(cfg.getExpiryMinutes());

        String ctrKey = key(NS_CTR,  epKey, bucketId);
        String ipsKey = key(NS_IPS,  epKey, bucketId);
        String seenKey = key(NS_SEEN, epKey, bucketId);

        // 1) Increment current minute count and track distinct IP
        Long x = redis.opsForValue().increment(ctrKey);
        redis.expire(ctrKey, ttl);

        String ip = firstNonEmpty(event.getIp(), event.getRemoteAddr(), "unknown");
        redis.opsForSet().add(ipsKey, ip);
        redis.expire(ipsKey, ttl);

        // 2) Mark this minute as "seen" once and increment samples for warm-up
        boolean firstSeen = Boolean.TRUE.equals(
                redis.opsForValue().setIfAbsent(seenKey, "1", ttl)
        );
        if (firstSeen) {
            redis.opsForValue().increment(key(NS_SAM, epKey));
        }

        // 3) Read baseline mean & variance (with safe defaults)
        double mean = readDouble(key(NS_MEAN, epKey), 0.0);
        double var  = readDouble(key(NS_VAR,  epKey), 1.0); // keep tiny variance to avoid div/0
        double std  = Math.max(Math.sqrt(var), 1e-6);

        // 4) Compute z-score for this minute's count
        long count = (x == null) ? 0L : x;
        double z = (count - mean) / std;

        // 5) Distinct IPs across sliding window
        int buckets = Math.max(1, cfg.getWindowMinutes() / cfg.getBucketMinutes());
        long distinctIps = unionDistinct(windowSetKeys(NS_IPS, epKey, epochMinute, buckets));

        // 6) Warm-up: only alert after enough distinct minutes observed
        long samples = readLong(key(NS_SAM, epKey), 0L);

        if (samples >= cfg.getMinSampleMinutes()
                && z >= cfg.getZThreshold()
                && distinctIps >= cfg.getMinDistinctIps()) {

            // Lock endpoint briefly and return mitigation verdict
            setLock(epKey, Duration.ofSeconds(cfg.getCoolOffSeconds()));

            String msg = String.format(
                    "Baseline surge on %s: count=%d, z=%.2f (μ=%.2f, σ=%.2f), distinctIPs=%d≥%d",
                    path, count, z, mean, std, distinctIps, cfg.getMinDistinctIps()
            );
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.TRAFFIC_SPIKE),
                    Arrays.asList("RATE_LIMIT_ENDPOINT", "CHALLENGE_ENDPOINT"),
                    msg
            ));
        }

        // 7) Update EWMA baseline (mean & variance)
        double alpha = clampAlpha(cfg.getAlpha());
        double mOld = mean;
        double mNew = (1.0 - alpha) * mOld + alpha * count;
        // EMA variance around old mean (stable, simple)
        double vNew = (1.0 - alpha) * (var + alpha * (count - mOld) * (count - mOld));
        writeDouble(key(NS_MEAN, epKey), mNew);
        writeDouble(key(NS_VAR,  epKey), Math.max(vNew, 1e-6));

        return Optional.empty();
    }

    /** Returns true if the given path matches any configured exclude pattern. */
    private boolean excluded(String path) {
        for (String pat : cfg.getExcludePatterns()) {
            if (path.toLowerCase(Locale.ROOT).contains(pat)) {
                return true;
            }
        }
        return false;
    }

    /** Builds a stable endpoint key from the path. Customize to normalize IDs if needed. */
    private static String endpointKey(String path) {
        return (path == null || path.isBlank()) ? "_" : path;
    }

    /** Constructs a namespaced Redis key of form 'ns:epKey[:bucketId]'. */
    private static String key(String ns, String epKey) {
        return ns + ":" + epKey;
    }

    /** Constructs a namespaced Redis key of form 'ns:epKey:bucketId'. */
    private static String key(String ns, String epKey, String bucketId) {
        return ns + ":" + epKey + ":" + bucketId;
    }

    /** Reads a double value from Redis or returns the provided default on null/parse error. */
    private double readDouble(String key, double def) {
        try {
            String v = redis.opsForValue().get(key);
            return (v == null) ? def : Double.parseDouble(v);
        } catch (RuntimeException ex) {
            return def;
        }
    }

    /** Writes a double value to Redis as a String. */
    private void writeDouble(String key, double value) {
        redis.opsForValue().set(key, Double.toString(value));
    }

    /** Reads a long value from Redis or returns the provided default on null/parse error. */
    private long readLong(String key, long def) {
        try {
            String v = redis.opsForValue().get(key);
            return (v == null) ? def : Long.parseLong(v);
        } catch (RuntimeException ex) {
            return def;
        }
    }

    /**
     * Returns the count of distinct members across multiple Redis Set keys by performing
     * an in-memory union. Keep the window small (e.g., 3-5 minutes) to bound cost.
     */
    private long unionDistinct(List<String> setKeys) {
        Set<String> acc = new HashSet<>();
        for (String k : setKeys) {
            Set<String> members = redis.opsForSet().members(k);
            if (members != null) acc.addAll(members);
        }
        return acc.size();
    }

    /** Builds the list of per-minute Set keys for the last N buckets for a given endpoint. */
    private List<String> windowSetKeys(String ns, String epKey, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> DetectorUtils.formatBucketId(epochMinute - (long) i * step, step))
                .map(bid -> key(ns, epKey, bid))
                .collect(Collectors.toList());
    }

    /** Returns true if an endpoint cool-off lock is active. */
    private boolean isLocked(String epKey) {
        Long ttl = redis.getExpire(NS_LOCK + ":" + epKey);
        return ttl > 0;
    }

    /** Sets a short-lived endpoint cool-off lock (value '1') with the given TTL. */
    private void setLock(String epKey, Duration ttl) {
        redis.opsForValue().set(NS_LOCK + ":" + epKey, "1", ttl);
    }

    /** Clamps EWMA alpha into a safe [0.01, 0.95] range. */
    private static double clampAlpha(double a) {
        if (a < 0.01) return 0.01;
        return Math.min(a, 0.95);
    }

    /** Returns the first non-empty string among a, b; otherwise returns def. */
    private static String firstNonEmpty(String a, String b, String def) {
        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;
        return def;
    }
}