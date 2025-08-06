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
 * This detector monitors the number of requests made from a specific device fingerprint within each minute.
 * It uses Redis to count requests per fingerprint and, if the count exceeds a configurable threshold,
 * flags the fingerprint as potentially abusive. The fingerprint is then added to a threat bucket for further action.
 * This helps protect against automated or abusive device activity.
 */
@Service
@RequiredArgsConstructor
public class DeviceAbuseDetector implements Detector {
    private final StringRedisTemplate redisTemplate;

    @Value("${deviceabuse.fingerprint.threshold:50}")
    private int fingerprintThreshold;

    @Value("${deviceabuse.fingerprint.expiry.minutes:15}")
    private int fingerprintExpiryMinutes;

    private final ThreatBucketService threatBucketService;


    @Override
    public Optional<DetectionVerdict> detect(SecurityEvent event) {
        String fpKey = "fpabuse:" + event.getDeviceFingerprint() + ":" + LocalDateTime.ofInstant(event.getTimestamp(), ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));

        Long fpCount = redisTemplate.opsForValue().increment(fpKey);
        redisTemplate.expire(fpKey, Duration.ofMinutes(fingerprintExpiryMinutes));

        if (fpCount != null && fpCount >= fingerprintThreshold) {
            threatBucketService.addToBucket(KeyManager.MALICIOUS_FINGERPRINT_BUCKET, event.getDeviceFingerprint());
            return Optional.of(new DetectionVerdict(
                    List.of(Constants.DEVICE_FINGERPRINT_ABUSE),
                    List.of("BLOCK_FINGERPRINT"),
                    "High number of requests from single device/browser."
            ));
        }
        return Optional.empty();
    }
}
