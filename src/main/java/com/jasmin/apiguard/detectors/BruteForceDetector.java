package com.jasmin.apiguard.detectors;

import com.jasmin.apiguard.constants.Constants;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

/**
 * This detector monitors login attempts and uses Redis to track the number of failed login attempts
 * per username and per IP address within each minute. If the number of attempts exceeds configurable
 * thresholds, it flags the activity as a potential brute-force attack. This helps protect against
 * automated attacks trying to guess user credentials.
 */
@Service
@RequiredArgsConstructor
public class BruteForceDetector implements Detector {
    private final StringRedisTemplate redisTemplate;

    @Value("${bruteforce.username.threshold:5}")
    private int usernameThreshold;

    @Value("${bruteforce.ip.threshold:20}")
    private int ipThreshold;

    @Value("${bruteforce.expiry.minutes:5}")
    private int bruteForceExpiryMinutes;

    @Value("${bruteforce.window.minutes:1}")
    private int windowMinutes;


    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        // Only process login actions; ignore other event types
        if (!"login".equals(event.getAction())) {
            return Optional.empty();
        }

        // Format the current minute for rate-limiting keys
        long epochMinute = event.getTimestamp().atZone(ZoneOffset.UTC).toEpochSecond() / 60;
        long windowBucket = epochMinute / windowMinutes * windowMinutes;
        String windowStartIso = LocalDateTime.ofEpochSecond(windowBucket * 60, 0, ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));

        String userKey = "bf:username:" + event.getUsername() + ":" + windowStartIso;
        String ipKey = "bf:ip:" + event.getIp() + ":" + windowStartIso;

        // Increment failed login counters in Redis for username and IP
        Long userFailCount = redisTemplate.opsForValue().increment(userKey);
        Long ipFailCount = redisTemplate.opsForValue().increment(ipKey);

        // Set expiration for counters to avoid indefinite growth
        redisTemplate.expire(userKey, Duration.ofMinutes(bruteForceExpiryMinutes));
        redisTemplate.expire(ipKey, Duration.ofMinutes(bruteForceExpiryMinutes));

        // If either threshold is exceeded, flag as brute-force attack
        if ((userFailCount != null && userFailCount > usernameThreshold) ||
            (ipFailCount != null && ipFailCount > ipThreshold)) {
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.BRUTE_FORCE_ATTACK),
                    List.of("LOCK_ACCOUNT", "BLOCK_IP"),
                    "Multiple failed logins detected"
            ));
        }
        // No brute-force detected
        return Optional.empty();
    }
}
