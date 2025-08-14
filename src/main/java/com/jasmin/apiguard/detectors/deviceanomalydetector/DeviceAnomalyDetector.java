package com.jasmin.apiguard.detectors.deviceanomalydetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import java.time.ZoneOffset;
import java.util.*;

@Service
@RequiredArgsConstructor
public class DeviceAnomalyDetector implements Detector {

    private static final Logger log = LoggerFactory.getLogger(DeviceAnomalyDetector.class);

    private static final String NS_LOCK     = "dsa:lock";
    private static final String NS_IPS      = "dsa:ips";
    private static final String NS_LASTIP   = "dsa:lastip";
    private static final String NS_IPSWITCH = "dsa:ipswitch";

    private final DeviceAnomalyProperties cfg;
    private final StringRedisTemplate redis;
    private final AntPathMatcher matcher = new AntPathMatcher();
    private static final RedisScript<List<Object>> LUA_SCRIPT = DetectorUtils.loadLuaScript("lua/device_anomaly.lua");

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        final String principal = principalId(event);
        if (principal == null || bypassed(principal, event)) return Optional.empty();
        if (isLocked(principal)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_ABUSE),
                    cfg.getActionsDuringLock(),
                    "Device principal in cool-off"
            ));
        }

        final String ip = DetectorUtils.nullSafe(event.getIp());
        final long now = event.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond();

        // Redis keys
        String zsetKey   = NS_IPS + ":" + principal;
        String lastIpKey = NS_LASTIP + ":" + principal;
        String switchKey = NS_IPSWITCH + ":" + principal;
        String lockKey   = NS_LOCK + ":" + principal;

        // Redis args
        List<String> keys = List.of(zsetKey, lastIpKey, switchKey, lockKey);
        List<String> args = List.of(
                ip,
                String.valueOf(now),
                String.valueOf(cfg.getWindowSeconds()),
                String.valueOf(cfg.getDistinctIpThreshold()),
                String.valueOf(cfg.getIpSwitchThreshold()),
                String.valueOf(cfg.getMaxIpsPerDevice()),
                String.valueOf(cfg.getCoolOffSeconds())
        );

        List<Object> result = redis.execute(LUA_SCRIPT, keys, args.toArray());
        if (result.size() < 3) {
            log.error("Lua script for device anomaly failed: principal={}", principal);
            return Optional.empty(); // fail open
        }

        boolean abuse = Long.parseLong(result.get(0).toString()) == 1;
        long ipFanout = Long.parseLong(result.get(1).toString());
        long ipChurn  = Long.parseLong(result.get(2).toString());

        if (abuse) {
            List<String> reasons = new ArrayList<>();
            List<String> actions = new ArrayList<>();

            if (ipFanout >= cfg.getDistinctIpThreshold()) {
                reasons.add("DEVICE_REUSED_ACROSS_IPS");
                actions.addAll(cfg.getActionsOnFanout());
            }

            if (ipChurn >= cfg.getIpSwitchThreshold()) {
                reasons.add("DEVICE_IP_HOPPING");
                actions.addAll(cfg.getActionsOnChurn());
            }

            actions = new ArrayList<>(new LinkedHashSet<>(actions)); // de-dup

            String msg = String.format(Locale.ROOT,
                    "Device abuse suspected: reasons=%s principal=%s uniqIp=%d ipSwitch=%d",
                    reasons,
                    principalSummary(principal),
                    ipFanout,
                    ipChurn
            );

            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_ABUSE),
                    actions,
                    msg
            ));
        }

        return Optional.empty();
    }

    private boolean bypassed(String principal, SecurityEvent e) {
        if (!cfg.isEnabled()) return true;
        if (cfg.getAllowlistIdentifiers().contains(stripPrefix(principal))) return true;
        if (cfg.getAllowlistIps().contains(DetectorUtils.nullSafe(e.getIp()))) return true;

        String path = DetectorUtils.nullSafe(e.getPath());
        for (String pat : cfg.getExcludePatterns()) {
            if (matcher.match(pat, path)) return true;
        }
        return false;
    }

    private boolean isLocked(String principal) {
        Long ttl = redis.getExpire(NS_LOCK + ":" + principal);
        return ttl > 0;
    }

    private String principalId(SecurityEvent e) {
        for (String name : cfg.getIdentifierHeaderCandidates()) {
            String v = DetectorUtils.firstHeaderMatch(e, Collections.singletonList(name));
            if (StringUtils.hasText(v)) {
                String id = v.trim();
                if (cfg.isIncludeUserAgentInPrincipal()) {
                    String ua = DetectorUtils.nullSafe(e.getUserAgent());
                    id += ":ua" + Integer.toHexString(ua.hashCode());
                }
                return "dev:" + id;
            }
        }

        if (cfg.isFallbackToIp() && StringUtils.hasText(e.getIp())) {
            String id = "ip:" + e.getIp().trim();
            if (cfg.isIncludeUserAgentInPrincipal()) {
                String ua = DetectorUtils.nullSafe(e.getUserAgent());
                id += ":ua" + Integer.toHexString(ua.hashCode());
            }
            return "dev:" + id;
        }

        return null;
    }

    private String stripPrefix(String principal) {
        return principal.startsWith("dev:") ? principal.substring(4) : principal;
    }

    private String principalSummary(String principal) {
        String s = stripPrefix(principal);
        return s.length() <= 10 ? s : "…" + s.substring(s.length() - 10);
    }
}
