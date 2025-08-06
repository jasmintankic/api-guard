package com.jasmin.apiguard.services;

import com.jasmin.apiguard.constants.Constants;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.EventAnalyticsResponse;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AnalyticsService {
    private final StringRedisTemplate redisTemplate;

    public EventAnalyticsResponse getEventStats(LocalDateTime from, LocalDateTime to) {
        List<String> eventKeys = new ArrayList<>();
        List<String> threatKeys = new ArrayList<>();
        List<String> threatTypes = List.of(Constants.BRUTE_FORCE_ATTACK, Constants.ENUMERATION_ATTACK, Constants.IP_ABUSE, Constants.REPLAY_ATTACK, Constants.DEVICE_FINGERPRINT_ABUSE, Constants.KNOWN_BAD_DEVICE, Constants.KNOWN_BAD_IP, Constants.KNOWN_BAD_CORRELATION_ID);

        Map<String, List<String>> threatTypeKeys = new HashMap<>();
        for (String threat : threatTypes) {
            threatTypeKeys.put(threat, new ArrayList<>());
        }

        for (LocalDateTime dt = from; !dt.isAfter(to); dt = dt.plusMinutes(1)) {
            String minuteKey = dt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd:HH:mm"));
            eventKeys.add(KeyManager.getEventsKey(minuteKey));
            threatKeys.add(KeyManager.getThreatsKey(minuteKey));

            for (String threat : threatTypes) {
                threatTypeKeys.get(threat).add("threat:" + threat + ":" + minuteKey);
            }
        }

        List<String> eventCounts = redisTemplate.opsForValue().multiGet(eventKeys);
        List<String> threatCounts = redisTemplate.opsForValue().multiGet(threatKeys);

        long totalEvents = eventCounts.stream()
                .filter(Objects::nonNull)
                .mapToLong(Long::parseLong).sum();

        long totalThreats = threatCounts.stream()
                .filter(Objects::nonNull)
                .mapToLong(Long::parseLong).sum();

        Map<String, Long> threatsByType = new HashMap<>();
        for (String threat : threatTypes) {
            List<String> keys = threatTypeKeys.get(threat);
            List<String> counts = redisTemplate.opsForValue().multiGet(keys);
            long sum = counts.stream().filter(Objects::nonNull).mapToLong(Long::parseLong).sum();
            threatsByType.put(threat, sum);
        }

        return new EventAnalyticsResponse(totalEvents, totalThreats, from, to, threatsByType);
    }
}
