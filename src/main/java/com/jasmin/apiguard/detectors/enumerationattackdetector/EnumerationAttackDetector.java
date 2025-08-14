package com.jasmin.apiguard.detectors.enumerationattackdetector;

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
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class EnumerationAttackDetector implements Detector {

    private static final String NS_HLL = "enum:hll";           // per-IP usernames
    private static final String NS_USERIPS_HLL = "enum:userips:hll"; // per-username IPs
    private static final String NS_ZSET = "enum:iprate:z";
    private static final String NS_LOCK = "enum:lock";

    private final StringRedisTemplate redis;
    private final EnumerationProperties cfg;
    private static final RedisScript<List<Object>> LUA_SCRIPT = DetectorUtils.loadLuaScript("/lua/enumeration.lua");

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (!cfg.isEnabled() || !DetectorUtils.isLoginAttempt(event)) {
            return Optional.empty();
        }

        String username = DetectorUtils.normalizeUsername(event.getUsername());
        String ip = DetectorUtils.nullSafe(event.getIp());

        if (username == null) return Optional.empty();

        String principal = principalKeyPart(event);
        long now = Instant.now().toEpochMilli();

        String usernameKey = NS_HLL + ":" + principal;
        String ipKey = NS_USERIPS_HLL + ":" + username;
        String zsetKey = NS_ZSET + ":" + principal;
        String lockKey = NS_LOCK + ":" + principal;

        if (isLocked(lockKey)) {
            return Optional.of(blockVerdict("Enumeration lock active"));
        }

        List<String> keys = List.of(usernameKey, ipKey, zsetKey, lockKey);
        List<String> args = List.of(
                username,
                ip,
                String.valueOf(now),
                String.valueOf(cfg.getBucketMinutes() * 60), // TTL
                String.valueOf(jitteredTtl(cfg.getCoolOffSeconds())),
                String.valueOf(cfg.getIpRateWindowSeconds() * 1000L),
                String.valueOf(cfg.getIpRateLimit()),
                String.valueOf(cfg.getThreshold()),
                String.valueOf(cfg.getUserIpsThreshold())
        );

        List<Object> result = redis.execute(LUA_SCRIPT, keys, args.toArray());
        if (result.size() != 4) {
            return Optional.empty(); // fail open
        }

        boolean triggered = Long.parseLong(result.getFirst().toString()) == 1;

        if (triggered) {
            String msg = String.format("Enumeration suspected username: [%s] from IP: [%s] ", username, ip);
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.ENUMERATION_ATTACK),
                    List.of("BLOCK_IP"),
                    msg
            ));
        }

        return Optional.empty();
    }

    private String principalKeyPart(SecurityEvent event) {
        String ip = DetectorUtils.nullSafe(event.getIp());
        if (!cfg.isIncludeUserAgentInPrincipal()) return "ip:" + ip;

        String ua = DetectorUtils.nullSafe(event.getUserAgent());
        int hash = ua.hashCode();
        return "ipua:" + ip + ":" + hash;
    }

    private boolean isLocked(String lockKey) {
        Long ttl = redis.getExpire(lockKey);
        return ttl > 0;
    }

    private static int jitteredTtl(int seconds) {
        int jitter = (int) Math.floor(seconds * (Math.random() * 0.10));
        return seconds + jitter;
    }

    private static DetectionVerdict blockVerdict(String reason) {
        return new DetectionVerdict(
                List.of(Constants.ENUMERATION_ATTACK),
                List.of("BLOCK_IP"),
                reason
        );
    }
}
