package com.jasmin.apiguard.services.threatstore;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ThreatStoreService {

    private final StringRedisTemplate redis;
    private final ThreatStoreProperties props;
    private final ObjectMapper objectMapper;

    private static final String INDEX_KEY = "ag:threats:index";

    public String save(SecurityEvent ev, DetectionVerdict v) {
        if (v.getThreats() == null || v.getThreats().isEmpty()) {
            return null;
        }

        String id = UUID.randomUUID().toString();
        long now = Instant.now().toEpochMilli();

        Map<String, String> h = new LinkedHashMap<>();
        h.put("ip", ev.getIp());
        h.put("method", ev.getMethod());
        h.put("path", ev.getPath());
        h.put("ua", ev.getUserAgent());
        h.put("headers", toJson(allowlistedHeaders(ev.getHeaders())));
        h.put("body", base64(truncate(ev.getBody(), props.getMaxBodyBytes())));
        h.put("threats", toJson(v.getThreats()));
        h.put("recs", toJson(v.getRecommendations()));
        h.put("corrId", ev.getCorrelationId());
        h.put("createdAt", Long.toString(now));

        String key = "ag:threat:" + id;
        redis.opsForHash().putAll(key, h);
        redis.expire(key, props.retentionDuration());

        redis.opsForZSet().add(INDEX_KEY, key, now);
        redis.expire(INDEX_KEY, props.retentionDuration());

        return id;
    }

    private Map<String, List<String>> allowlistedHeaders(Map<String, List<String>> headers) {
        Set<String> allow = props.getHeaderAllowlist().stream()
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (allow.contains(e.getKey().toLowerCase())) {
                out.put(e.getKey(), e.getValue());
            }
        }
        return out;
    }

    private byte[] truncate(byte[] body, int max) {
        if (body == null) return new byte[0];
        if (body.length <= max) return body;
        return Arrays.copyOf(body, max);
    }

    private String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data == null ? new byte[0] : data);
    }

    private String toJson(Object o) {
        try {
            return objectMapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}