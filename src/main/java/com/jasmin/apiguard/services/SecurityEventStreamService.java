package com.jasmin.apiguard.services;

import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SecurityEventStreamService {
    private static final String STREAM_KEY = "security:events";

    private final StringRedisTemplate redisTemplate;

    public void publishEvent(SecurityEvent event, DetectionVerdict verdict) {
        Map<String, String> data = new HashMap<>();
        data.put("ip", event.getIp());
        data.put("username", event.getUsername());
        data.put("fingerprint", event.getDeviceFingerprint());
        data.put("action", event.getAction());
        data.put("status", event.getStatus());
        data.put("endpoint", event.getEndpoint());
        data.put("timestamp", event.getTimestamp().toString());
        data.put("threats", String.join(",", verdict.getThreats()));
        data.put("recommendations", String.join(",", verdict.getRecommendations()));
        data.put("details", verdict.getDetails());

        incrementEventCounters(event, verdict);
        redisTemplate.opsForStream().add(STREAM_KEY, data);
    }

    public void incrementEventCounters(SecurityEvent event, DetectionVerdict verdict) {
        LocalDateTime eventTime = LocalDateTime.ofInstant(event.getTimestamp(), ZoneOffset.UTC);
        String minuteKey = eventTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd:HH:mm"));
        String eventKey = "events:" + minuteKey;

        redisTemplate.opsForValue().increment(eventKey);

        if (verdict.getThreats() != null && !verdict.getThreats().isEmpty()) {
            String threatKey = KeyManager.getThreatsKey(minuteKey);
            redisTemplate.opsForValue().increment(threatKey);

            // NEW: Per-threat-type counters
            for (String threat : verdict.getThreats()) {
                String threatTypeKey = "threat:" + threat + ":" + minuteKey;
                redisTemplate.opsForValue().increment(threatTypeKey);
                redisTemplate.expire(threatTypeKey, Duration.ofDays(40));
            }
            redisTemplate.expire(threatKey, Duration.ofDays(40));
        }

        redisTemplate.expire(eventKey, Duration.ofDays(40));
    }


}
