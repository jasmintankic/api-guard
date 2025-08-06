package com.jasmin.apiguard.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityAlertPublisher {
    private static final String ALERT_CHANNEL = "security:alerts";

    private final StringRedisTemplate redisTemplate;

    public void publishAlert(SecurityEvent event, DetectionVerdict verdict) {
        Map<String, Object> alert = new HashMap<>();
        alert.put("ip", event.getIp());
        alert.put("username", event.getUsername());
        alert.put("fingerprint", event.getDeviceFingerprint());
        alert.put("action", event.getAction());
        alert.put("status", event.getStatus());
        alert.put("endpoint", event.getEndpoint());
        alert.put("timestamp", event.getTimestamp().toString());
        alert.put("threats", verdict.getThreats());
        alert.put("recommendations", verdict.getRecommendations());
        alert.put("details", verdict.getDetails());

        try {
            String alertJson = new ObjectMapper().writeValueAsString(alert);
            redisTemplate.convertAndSend(ALERT_CHANNEL, alertJson);
        } catch (Exception e) {
            log.error("Failed to persist alert json", e);
        }
    }
}
