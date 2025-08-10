package com.jasmin.apiguard.services.threatstore;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class ThreatQueryService {
    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;

    public ThreatRangeResponse query(Instant from, Instant to, int samplesPerIp) {
        // Treat non-positive as "no cap"
        final int cap = samplesPerIp > 0 ? samplesPerIp : Integer.MAX_VALUE;

        Set<String> keys = redis.opsForZSet()
                .rangeByScore("ag:threats:index", from.toEpochMilli(), to.toEpochMilli());

        ThreatRangeResponse resp = new ThreatRangeResponse();
        resp.setFrom(from);
        resp.setTo(to);
        resp.setTotalThreatEvents(keys == null ? 0 : keys.size());

        if (keys == null || keys.isEmpty()) {
            resp.setIps(List.of());
            return resp;
        }

        // Keep IP order stable by latest activity (we'll compute latestAt as we go)
        Map<String, ThreatIpGroup> grouped = new HashMap<>();
        // Per-IP min-heap to retain only the latest N samples per IP
        Map<String, PriorityQueue<ThreatSample>> perIpHeaps = new HashMap<>();

        for (String key : keys) {
            Map<Object, Object> h = redis.opsForHash().entries(key);
            if (h == null || h.isEmpty()) continue;

            // Required fields
            String createdAtRaw = (String) h.get("createdAt");
            Long createdAtMs = safeParseLong(createdAtRaw);
            if (createdAtMs == null) continue; // can't rank without timestamp

            String ip = (String) h.getOrDefault("ip", "unknown");
            String eventId = key.startsWith("ag:threat:") ? key.substring("ag:threat:".length()) : key;

            // Create/refresh the IP group
            ThreatIpGroup grp = grouped.computeIfAbsent(ip, k -> {
                ThreatIpGroup g = new ThreatIpGroup();
                g.setIp(ip);
                return g;
            });

            grp.setCount(grp.getCount() + 1);
            if (grp.getLatestAt() == null || createdAtMs > grp.getLatestAt().toEpochMilli()) {
                grp.setLatestAt(Instant.ofEpochMilli(createdAtMs));
            }

            // Build the full sample (do NOT trim threats/headers/etc)
            ThreatSample s = new ThreatSample();
            s.setId(eventId);
            s.setAt(Instant.ofEpochMilli(createdAtMs));
            s.setMethod((String) h.get("method"));
            s.setUrl((String) h.get("path")); // full request target
            s.setUa((String) h.get("ua"));
            s.setThreats(fromJson((String) h.get("threats"), List.class));
            s.setRecommendations(fromJson((String) h.get("recs"), List.class));
            s.setHeaders(fromJson((String) h.get("headers"), Object.class));
            s.setBodyB64((String) h.get("body"));
            s.setCorrId((String) h.get("corrId"));

            // Per-IP heap (min by timestamp). Keep only the latest `cap`.
            PriorityQueue<ThreatSample> pq = perIpHeaps.computeIfAbsent(
                    ip, k -> new PriorityQueue<>(Comparator.comparing(ThreatSample::getAt))
            );
            pq.offer(s);
            if (pq.size() > cap) {
                pq.poll(); // drop the oldest -> retain only the latest `cap`
            }
        }

        // Materialize samples per IP, newest-first, and attach to groups
        List<ThreatIpGroup> result = new ArrayList<>(grouped.values());
        for (ThreatIpGroup grp : result) {
            PriorityQueue<ThreatSample> pq = perIpHeaps.get(grp.getIp());
            if (pq == null || pq.isEmpty()) {
                grp.setSamples(Collections.emptyList());
                continue;
            }
            List<ThreatSample> samples = new ArrayList<>(pq);
            samples.sort(Comparator.comparing(ThreatSample::getAt).reversed());
            grp.setSamples(samples);
        }

        resp.setIps(result);
        return resp;
    }

    private static Long safeParseLong(String v) {
        if (v == null) return null;
        try { return Long.parseLong(v); } catch (NumberFormatException e) { return null; }
    }


    public Map<Object, Object> getFullEvent(String eventId) {
        String key = "ag:threat:" + eventId;
        Map<Object, Object> h = redis.opsForHash().entries(key);
        if (h.isEmpty()) return null;
        return h;
    }

    private <T> T fromJson(String json, Class<T> type) {
        if (json == null) return null;
        try {
            return objectMapper.readValue(json, type);
        } catch (Exception e) {
            return null;
        }
    }
}