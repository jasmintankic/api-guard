package com.jasmin.apiguard.detectors.bruteforcedetector;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.detectors.DetectorUtils;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class BruteForceDetector implements Detector {

    private final StringRedisTemplate redis;
    private final BruteForceProperties cfg;

    // ZSET namespaces (new)
    private static final String NS_Z_USER = "bf:z:user";      // bf:z:user:<username>
    private static final String NS_Z_IP = "bf:z:ip";        // bf:z:ip:<ip>
    private static final String NS_Z_USER_IP = "bf:z:userip";    // bf:z:userip:<username>:<ip>

    // Lock namespaces (same idea as before, but explicit per scope)
    private static final String NS_LOCK_USER = "bf:lock:user";     // bf:lock:user:<username>
    private static final String NS_LOCK_IP = "bf:lock:ip";       // bf:lock:ip:<ip>
    private static final String NS_LOCK_USER_IP = "bf:lock:userip";   // bf:lock:userip:<username>:<ip>

    private static final RedisScript<List<Object>> LUA_SCRIPT = DetectorUtils.loadLuaScript("lua/brute_force.lua");

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (!cfg.isEnabled() || !DetectorUtils.isLoginAttempt(event)) {
            return Optional.empty();
        }

        final String username = DetectorUtils.normalizeValue(DetectorUtils.nullSafe(event.getUsername()));
        final String ip = DetectorUtils.nullSafe(event.getIp());
        if (username == null || ip == null) {
            return Optional.empty();
        }

        // Fast path: if any lock is active, return verdict immediately (no mutation)
        String lockUserKey = lockUser(username);
        String lockIpKey = lockIp(ip);
        String lockUserIpKey = lockUserIp(username, ip);
        if (isActive(lockUserKey) || isActive(lockIpKey) || isActive(lockUserIpKey)) {
            return Optional.of(verdictLocked("Potential Brute-force attack active"));
        }

        // Compose ZSET keys
        String zUserKey = zUser(username);
        String zIpKey = zIp(ip);
        String zUserIpKey = zUserIp(username, ip);

        long nowMs = Instant.now().toEpochMilli();
        long windowMs = toWindowMs();
        int lockTtlSec = cfg.getCoolOffSeconds();

        int thUser = cfg.getThreshold().getUsername();
        int thIp = cfg.getThreshold().getIp();
        int thUserIp = cfg.getThreshold().getUserIp();

        int maxEventsPerScope = Math.max(0, cfg.getMaxEventsPerScope()); // 0 => no cap
        String uniq = UUID.randomUUID().toString();

        List<String> keys = List.of(
                zUserKey, zIpKey, zUserIpKey,
                lockUserKey, lockIpKey, lockUserIpKey
        );

        List<String> args = List.of(
                String.valueOf(nowMs),
                String.valueOf(windowMs),
                String.valueOf(lockTtlSec),
                String.valueOf(thUser),
                String.valueOf(thIp),
                String.valueOf(thUserIp),
                String.valueOf(maxEventsPerScope),
                uniq
        );

        List<Object> res = redis.execute(LUA_SCRIPT, keys, args.toArray());
        if (res.size() != 6) {
            return Optional.empty();
        }

        long userCount = Long.parseLong(res.get(0).toString());
        boolean userLocked = Long.parseLong(res.get(1).toString()) == 1L;
        long ipCount = Long.parseLong(res.get(2).toString());
        boolean ipLocked = Long.parseLong(res.get(3).toString()) == 1L;
        long userIpCount = Long.parseLong(res.get(4).toString());
        boolean userIpLocked = Long.parseLong(res.get(5).toString()) == 1L;

        if (userLocked || ipLocked || userIpLocked) {
            String msg = String.format(
                    Locale.ROOT,
                    "Multiple failed logins (u=%d/%d, ip=%d/%d, uip=%d/%d) within %d-second window",
                    userCount, thUser, ipCount, thIp, userIpCount, thUserIp, windowMs / 1000
            );

            // Optional: tailor actions by which scope tripped. Keeping your original actions:
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.BRUTE_FORCE_ATTACK),
                    Arrays.asList("LOCK_ACCOUNT", "BLOCK_IP", "RETRY_LATER"),
                    msg
            ));
        }

        return Optional.empty();
    }

    private String zUser(String username) {
        return NS_Z_USER + ":" + username;
    }

    private String zIp(String ip) {
        return NS_Z_IP + ":" + ip;
    }

    private String zUserIp(String u, String ip) {
        return NS_Z_USER_IP + ":" + u + ":" + ip;
    }

    private String lockUser(String username) {
        return NS_LOCK_USER + ":" + username;
    }

    private String lockIp(String ip) {
        return NS_LOCK_IP + ":" + ip;
    }

    private String lockUserIp(String u, String ip) {
        return NS_LOCK_USER_IP + ":" + u + ":" + ip;
    }

    private boolean isActive(String lockKey) {
        Long ttl = redis.getExpire(lockKey);
        return ttl > 0;
    }

    private long toWindowMs() {
        return Math.max(1, cfg.getWindowSeconds()) * 1000L;
    }

    private static DetectionVerdict verdictLocked(String reason) {
        return new DetectionVerdict(
                List.of(Constants.BRUTE_FORCE_ATTACK),
                Arrays.asList("LOCK_ACCOUNT", "BLOCK_IP", "RETRY_LATER"),
                reason
        );
    }
}
