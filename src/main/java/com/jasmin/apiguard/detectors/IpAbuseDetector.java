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
 * This detector monitors the number of requests from a single IP address within each minute.
 * It uses Redis to count requests per IP and, if the count exceeds a configurable threshold,
 * flags the IP as potentially abusive. The IP is then added to a threat bucket for further action.
 * This helps protect against automated or abusive activity from a single IP address.
 */
@Service
@RequiredArgsConstructor
public class IpAbuseDetector implements Detector {
    private final StringRedisTemplate redisTemplate;
    private final ThreatBucketService threatBucketService;

    @Value("${ipabuse.threshold:100}")
    private int ipThreshold;

    @Value("${ipabuse.expiry.minutes:2}")
    private int ipAbuseExpiryMinutes;

    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        String ipKey = "ipabuse:" + event.getIp() + ":" + LocalDateTime.ofInstant(event.getTimestamp(), ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));

        Long ipCount = redisTemplate.opsForValue().increment(ipKey);
        redisTemplate.expire(ipKey, Duration.ofMinutes(ipAbuseExpiryMinutes));

        if (ipCount != null && ipCount > ipThreshold) {
            threatBucketService.addToBucket(KeyManager.MALICIOUS_IP_BUCKET, event.getIp());
            return Optional.of(new DetectionVerdict(List.of(Constants.IP_ABUSE),
                    List.of("BLOCK_IP"),
                    "High number of requests from single IP."));
        }

        return Optional.empty();
    }
}
