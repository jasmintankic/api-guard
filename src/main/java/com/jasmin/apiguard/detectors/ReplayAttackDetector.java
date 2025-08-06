package com.jasmin.apiguard.detectors;

import com.jasmin.apiguard.constants.Constants;
import com.jasmin.apiguard.services.KeyManager;
import com.jasmin.apiguard.services.ThreatBucketService;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * This detector monitors for replay attacks by checking if a request with the same username,
 * action has already been processed within a configurable time window.
 * It uses Redis to store a unique key for each request and, if a duplicate is detected within
 * the window, flags the activity as a replay attack. This helps prevent attackers from
 * resubmitting the same request multiple times.
 */
@Service
@RequiredArgsConstructor
public class ReplayAttackDetector implements Detector {
    private final StringRedisTemplate redisTemplate;

    @Value("${replay.window.millis:120000}")
    private int replayWindowMillis;

    @Value("${replay.trigger.threshold:3}")
    private int replayTriggerThreshold;

    private final ThreatBucketService threatBucketService;

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        if (event.getAction() == null || event.getUsername() == null) {
            return Optional.empty();
        }

        Duration replayWindow = Duration.ofMillis(replayWindowMillis);
        String replayKey = "replay:" + event.getUsername() + ":" + event.getAction() + ":" + event.getCorrelationId();

        // Increment the replay count for this key
        Long count = redisTemplate.opsForValue().increment(replayKey);

        // Set expiry only on the first increment
        if (count != null && count == 1) {
            redisTemplate.expire(replayKey, replayWindow);
        }

        // Trigger only if count exceeds threshold
        if (count != null && count > replayTriggerThreshold) {
            threatBucketService.addToBucket(KeyManager.MALICIOUS_CORRELATION_ID_BUCKET, event.getIp());
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.REPLAY_ATTACK),
                    List.of("REJECT_REQUEST"),
                    "Replay attack: request has been seen " + count + " times"
            ));
        }

        return Optional.empty();
    }
}
