package com.jasmin.apiguard.detectors.deviceanomalydetector;

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
public class DeviceAnomalyDetector implements Detector {

    // Per-bucket distinct sets
    private static final String NS_DU = "devanom:du"; // devicePrincipal -> distinct usernames
    private static final String NS_UD = "devanom:ud"; // userPrincipal   -> distinct devicePrincipals
    private static final String NS_DI = "devanom:di"; // devicePrincipal -> distinct IPs

    // Cool-off locks
    private static final String NS_LOCK_DEVICE = "devanom:lock:device";
    private static final String NS_LOCK_USER   = "devanom:lock:user";

    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    private final StringRedisTemplate redis;
    private final ThreatBucketService threatBucketService;
    private final DeviceAnomalyProperties cfg;

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        final String username = safeLower(event.getUsername());
        final String ip       = firstNonEmpty(event.getIp(), event.getRemoteAddr(), "unknown");
        final String ua       = headerFirst(event, "User-Agent");

        // You guarantee exactly ONE of these per request:
        final String vendorId   = firstHeaderMatch(event, cfg.getVendorIdHeaderNames());
        final String fingerprint = firstHeaderMatch(event, cfg.getFingerprintHeaderNames());

        // Pick whichever is present; if both somehow present, prefer vendorId.
        final String deviceId;
        final String deviceType;
        if (!vendorId.isBlank()) {
            deviceId = vendorId;
            deviceType = "vendor";
        } else if (!fingerprint.isBlank()) {
            deviceId = fingerprint;
            deviceType = "fingerprint";
        } else {
            return Optional.empty(); // nothing to key on
        }

        final String devicePrincipal = devicePrincipal(deviceType, deviceId, ua);
        final String userPrincipal   = "user:" + (username.isBlank() ? "unknown" : username);

        // Pre-lock short-circuit
        if (isLocked(NS_LOCK_DEVICE, devicePrincipal) || isLocked(NS_LOCK_USER, userPrincipal)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_ABUSE),
                    Arrays.asList("BLOCK_DEVICE", "LOCK_ACCOUNT", "RETRY_LATER"),
                    "Device/user in cool-off window"
            ));
        }

        // Current bucket
        long epochMinute = event.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond() / 60;
        String bucketId = formatBucketId(epochMinute, cfg.getBucketMinutes());
        Duration ttl = Duration.ofMinutes(cfg.getExpiryMinutes());

        String kDU = NS_DU + ":" + devicePrincipal + ":" + bucketId;
        String kUD = NS_UD + ":" + userPrincipal   + ":" + bucketId;
        String kDI = NS_DI + ":" + devicePrincipal + ":" + bucketId;

        if (!username.isBlank()) {
            redis.opsForSet().add(kDU, username);
            redis.expire(kDU, ttl);
        }
        redis.opsForSet().add(kUD, devicePrincipal);
        redis.expire(kUD, ttl);

        redis.opsForSet().add(kDI, ip);
        redis.expire(kDI, ttl);

        // Sliding-window distinct counts
        int bucketsToSum = Math.max(1, cfg.getWindowMinutes() / cfg.getBucketMinutes());

        long usersPerDevice = unionSize(windowKeys(NS_DU, devicePrincipal, epochMinute, bucketsToSum));
        long devsPerUser    = unionSize(windowKeys(NS_UD, userPrincipal,   epochMinute, bucketsToSum));
        long ipsPerDevice   = unionSize(windowKeys(NS_DI, devicePrincipal, epochMinute, bucketsToSum));

        boolean tripDU = usersPerDevice > cfg.getThresholdUsersPerDevice();
        boolean tripUD = devsPerUser    > cfg.getThresholdDevicesPerUser();
        boolean tripDI = ipsPerDevice   > cfg.getThresholdIpsPerDevice();

        if (tripDU || tripUD || tripDI) {
            // Locks & threat buckets
            if (tripDU || tripDI) {
                setLock(NS_LOCK_DEVICE, devicePrincipal, Duration.ofSeconds(cfg.getCoolOffSeconds()));
                threatBucketService.addToBucket(KeyManager.MALICIOUS_DEVICE_BUCKET, devicePrincipal);
                if (!"unknown".equals(ip)) {
                    threatBucketService.addToBucket(KeyManager.MALICIOUS_IP_BUCKET, ip);
                }
            }
            if (tripUD) {
                setLock(NS_LOCK_USER, userPrincipal, Duration.ofSeconds(cfg.getCoolOffSeconds()));
                if (!username.isBlank()) {
                    threatBucketService.addToBucket(KeyManager.MALICIOUS_USERNAME_BUCKET, username);
                }
            }

            String msg = String.format(
                    "Device anomaly (%s): dev→users=%d/%d, user→devices=%d/%d, dev→IPs=%d/%d (window=%d min)",
                    deviceType,
                    usersPerDevice, cfg.getThresholdUsersPerDevice(),
                    devsPerUser,    cfg.getThresholdDevicesPerUser(),
                    ipsPerDevice,   cfg.getThresholdIpsPerDevice(),
                    cfg.getWindowMinutes()
            );

            List<String> actions = new ArrayList<>();
            if (tripDU || tripDI) actions.add("BLOCK_DEVICE");
            if (tripUD)           actions.add("LOCK_ACCOUNT");
            if (tripDI)           actions.add("BLOCK_IP");
            actions.add("RETRY_LATER");

            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_ABUSE),
                    actions,
                    msg
            ));
        }

        return Optional.empty();
    }

    /* ================= helpers ================= */

    private static String safeLower(String s) {
        return (s == null || s.isBlank()) ? "" : s.toLowerCase(Locale.ROOT);
    }

    private String firstHeaderMatch(SecurityEvent e, List<String> names) {
        if (e.getHeaders() == null || names == null) return "";
        for (String n : names) {
            for (Map.Entry<String, List<String>> en : e.getHeaders().entrySet()) {
                if (en.getKey() != null && en.getKey().equalsIgnoreCase(n)) {
                    List<String> vals = en.getValue();
                    if (vals != null && !vals.isEmpty() && vals.get(0) != null && !vals.get(0).isBlank()) {
                        return vals.get(0).trim();
                    }
                }
            }
        }
        return "";
    }

    private String headerFirst(SecurityEvent e, String name) {
        if (e.getHeaders() == null || name == null) return "";
        for (Map.Entry<String, List<String>> en : e.getHeaders().entrySet()) {
            if (en.getKey() != null && en.getKey().equalsIgnoreCase(name)) {
                List<String> vals = en.getValue();
                return (vals == null || vals.isEmpty()) ? "" : Optional.ofNullable(vals.get(0)).orElse("");
            }
        }
        return "";
    }

    private String devicePrincipal(String type, String id, String userAgent) {
        if (cfg.isIncludeUserAgentInPrincipal()) {
            int uaHash = (userAgent == null) ? 0 : userAgent.hashCode();
            return "dev:" + type + ":" + id + ":ua:" + uaHash;
        }
        return "dev:" + type + ":" + id;
    }

    private static String formatBucketId(long epochMinute, int bucketMinutes) {
        long aligned = (epochMinute / bucketMinutes) * bucketMinutes;
        return LocalDateTime.ofEpochSecond(aligned * 60, 0, ZoneOffset.UTC).format(BUCKET_FMT);
    }

    private List<String> windowKeys(String ns, String id, long epochMinute, int bucketsToSum) {
        int step = cfg.getBucketMinutes();
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> formatBucketId(epochMinute - (long) i * step, step))
                .map(bucketId -> ns + ":" + id + ":" + bucketId)
                .collect(Collectors.toList());
    }

    /** In-memory union across per-bucket sets for simple, exact distinct counts. */
    private long unionSize(List<String> keys) {
        Set<String> acc = new HashSet<>();
        for (String k : keys) {
            Set<String> members = redis.opsForSet().members(k);
            if (members != null) acc.addAll(members);
        }
        return acc.size();
    }

    private boolean isLocked(String ns, String id) {
        Long ttlSec = redis.getExpire(ns + ":" + id);
        return ttlSec > 0;
    }

    private void setLock(String ns, String id, Duration ttl) {
        redis.opsForValue().set(ns + ":" + id, "1", ttl);
    }
}
