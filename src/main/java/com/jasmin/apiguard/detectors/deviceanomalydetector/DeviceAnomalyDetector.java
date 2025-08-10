package com.jasmin.apiguard.detectors.deviceanomalydetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.ZoneOffset;
import java.util.*;

@Service
@RequiredArgsConstructor
public class DeviceAnomalyDetector implements Detector {

    private static final String NS_LOCK     = "dsa:lock";     // cool-off lock
    private static final String NS_IPS      = "dsa:ips";      // ZSET(ip -> lastSeenEpochSec)
    private static final String NS_LASTIP   = "dsa:lastip";   // last observed IP
    private static final String NS_IPSWITCH = "dsa:ipswitch"; // count of ip switches (TTL window)

    private final DeviceAnomalyProperties cfg;
    private final StringRedisTemplate redis;
    private final AntPathMatcher matcher = new AntPathMatcher();

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        // 1) principal from ordered headers
        final String principal = principalId(event); // device identifier which is picked vendor id or something else
        if (principal == null) {
            return Optional.empty();
        }

        if (bypassed(principal, event)) {
            return Optional.empty();
        }

        // 2) active cool-off lock?
        if (isLocked(principal)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_ABUSE),
                    cfg.getActionsDuringLock(),
                    "Device principal in cool-off"
            ));
        }

        // 3) signals
        final String ip = DetectorUtils.nullSafe(event.getIp());
        final long now = event.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond();
        double fanout = distinctIpSignal(principal, ip, now); // normalized 0..1
        double churn  = ipChurnSignal(principal, ip);         // normalized 0..1

        // 4) decisions
        boolean deviceReused = fanout >= 1.0;
        boolean deviceHoping  = churn  >= 1.0;

        if (deviceReused || deviceHoping) {
            List<String> reasons = new ArrayList<>();
            if (deviceReused) {
                reasons.add("DEVICE_REUSED_ACROSS_IPS");
            }

            if (deviceHoping) {
                reasons.add("DEVICE_IP_HOPPING");
            }

            List<String> actions = new ArrayList<>();
            if (deviceReused) actions.addAll(cfg.getActionsOnFanout());
            if (deviceHoping)  actions.addAll(cfg.getActionsOnChurn());
            actions = new ArrayList<>(new LinkedHashSet<>(actions)); // de-dup

            if (actions.stream().anyMatch(a -> a.startsWith("BLOCK"))) {
                lockPrincipal(principal, Duration.ofSeconds(cfg.getCoolOffSeconds()));
            }

            String msg = String.format(Locale.ROOT,
                    "Device abuse suspected: reasons=%s principal=%s uniqIp>=%d?%s ipSwitch>=%d?%s",
                    reasons,
                    principalSummary(principal),
                    cfg.getDistinctIpThreshold(), deviceReused,
                    cfg.getIpSwitchThreshold(), deviceHoping
            );

            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_ABUSE),
                    actions,
                    msg
            ));
        }

        return Optional.empty();
    }

    private String principalId(SecurityEvent e) {
        for (String name : cfg.getIdentifierHeaderCandidates()) {
            String v = DetectorUtils.firstHeaderMatch(e, Collections.singletonList(name));
            if (StringUtils.hasText(v)) {
                String id = v.trim();
                if (cfg.isIncludeUserAgentInPrincipal()) {
                    String ua = DetectorUtils.nullSafe(e.getUserAgent());
                    id = id + ":ua" + Integer.toHexString(ua.hashCode());
                }
                return "dev:" + id;
            }
        }
        if (cfg.isFallbackToIp() && StringUtils.hasText(e.getIp())) {
            String id = "ip:" + e.getIp().trim();
            if (cfg.isIncludeUserAgentInPrincipal()) {
                String ua = DetectorUtils.nullSafe(e.getUserAgent());
                id = id + ":ua" + Integer.toHexString(ua.hashCode());
            }
            return "dev:" + id;
        }
        return null;
    }

    private boolean bypassed(String principal, SecurityEvent e) {
        if (cfg.getAllowlistIdentifiers().contains(stripPrefix(principal))) {
            return true;
        }

        if (cfg.getAllowlistIps().contains(DetectorUtils.nullSafe(e.getIp()))) {
            return true;
        }

        String ep = DetectorUtils.nullSafe(e.getPath());

        for (String pat : cfg.getExcludePatterns()) {
            if (matcher.match(pat, ep)) return true;
        }

        return false;
    }

    // ZSET of IPs last seen within window; normalize by threshold
    private double distinctIpSignal(String principal, String ip, long now) {
        if (!StringUtils.hasText(ip)) return 0.0;
        String key = key(NS_IPS, principal);
        ZSetOperations<String, String> z = redis.opsForZSet();
        z.add(key, ip, now);
        z.removeRangeByScore(key, 0, now - cfg.getWindowSeconds());
        Long card = z.zCard(key);
        redis.expire(key, Duration.ofSeconds(cfg.getWindowSeconds() * 2L));
        long uniq = card == null ? 0L : card;
        return Math.min(1.0, uniq / Math.max(1.0, (double) cfg.getDistinctIpThreshold()));
    }

    // Count back-to-back IP changes inside the window; normalize by threshold
    private double ipChurnSignal(String principal, String ip) {
        if (!StringUtils.hasText(ip)) return 0.0;
        String lastKey = key(NS_LASTIP, principal);
        String prev = redis.opsForValue().get(lastKey);
        if (!ip.equals(prev)) {
            String swKey = key(NS_IPSWITCH, principal);
            Long v = redis.opsForValue().increment(swKey);
            redis.expire(swKey, Duration.ofSeconds(cfg.getWindowSeconds()));
            redis.opsForValue().set(lastKey, ip, Duration.ofSeconds(cfg.getWindowSeconds()));
            long switches = v == null ? 0L : v;
            return Math.min(1.0, switches / Math.max(1.0, (double) cfg.getIpSwitchThreshold()));
        } else {
            redis.expire(lastKey, Duration.ofSeconds(cfg.getWindowSeconds()));
            return 0.0;
        }
    }

    private boolean isLocked(String principal) {
        Long ttl = redis.getExpire(key(NS_LOCK, principal));
        return ttl > 0;
    }

    private void lockPrincipal(String principal, Duration ttl) {
        redis.opsForValue().set(key(NS_LOCK, principal), "1", ttl);
    }

    private String key(String ns, String principal) {
        return ns + ":" + principal;
    }

    private String stripPrefix(String principal) {
        return principal.startsWith("dev:") ? principal.substring(4) : principal;
    }

    private String principalSummary(String principal) {
        String s = stripPrefix(principal);
        return s.length() <= 10 ? s : "…" + s.substring(s.length() - 10);
    }
}