package com.jasmin.apiguard.detectors;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.services.KeyManager;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import com.jasmin.apiguard.services.ThreatBucketService;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

/**
 * This detector monitors for enumeration attacks by tracking the number of unique usernames
 * attempted from a single IP address within each minute. It uses Redis to store each unique
 * username per IP and, if the count exceeds a configurable threshold, flags the activity as
 * a potential enumeration attack. This helps protect against attackers trying to discover
 * valid usernames through repeated login attempts.
 */
@Service
@RequiredArgsConstructor
public class EnumerationAttackDetector implements Detector {
    private final StringRedisTemplate redisTemplate;
    private final ThreatBucketService threatBucketService;

    @Value("${enumeration.threshold:20}")
    private int enumThreshold;

    @Value("${enumeration.expiry.minutes:2}")
    private int enumerationExpiryMinutes;

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        String identifier = event.getUsername();

        if (identifier == null) {
            return Optional.empty();
        }

        String minutePartOfKey = LocalDateTime.ofInstant(event.getTimestamp(), ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));
        String enumKey = "enum:" + event.getIp() + ":" + minutePartOfKey;

        Long count = redisTemplate.opsForSet().add(enumKey, identifier);
        redisTemplate.expire(enumKey, Duration.ofMinutes(enumerationExpiryMinutes)); // Cleanup after

        Long uniqueCount = redisTemplate.opsForSet().size(enumKey);

        if (uniqueCount != null && uniqueCount >= enumThreshold) {
            threatBucketService.addToBucket(KeyManager.MALICIOUS_IP_BUCKET, event.getIp());
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.ENUMERATION_ATTACK),
                    List.of("BLOCK_IP"),
                    "Multiple unique usernames attempted from single IP"
            ));
        }

        return Optional.empty();
    }
}
