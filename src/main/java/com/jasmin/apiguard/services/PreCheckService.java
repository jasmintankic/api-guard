package com.jasmin.apiguard.services;

import com.jasmin.apiguard.constants.Constants;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PreCheckService {
    private final ThreatBucketService threatBucketService;

    public DetectionVerdict preCheck(SecurityEvent event) {
        if (threatBucketService.isInBucket(KeyManager.MALICIOUS_IP_BUCKET, event.getIp())) {
            return new DetectionVerdict(
                            List.of(Constants.KNOWN_BAD_IP),
                            List.of("BLOCK_IP"),
                            "IP address is flagged as malicious"
                    );
        }

        if (threatBucketService.isInBucket(KeyManager.MALICIOUS_FINGERPRINT_BUCKET, event.getDeviceFingerprint())) {
            return new DetectionVerdict(
                    List.of(Constants.KNOWN_BAD_DEVICE),
                    List.of("LOCK_ACCOUNT"),
                    "Device is flagged as malicious"
            );
        }

        if (threatBucketService.isInBucket(KeyManager.MALICIOUS_CORRELATION_ID_BUCKET, event.getDeviceFingerprint())) {
            return new DetectionVerdict(
                    List.of(Constants.KNOWN_BAD_CORRELATION_ID),
                    List.of("BLOCK_IP", "BLOCK_DEVICE"),
                    "API call flagged as malicious"
            );
        }

        return null;
    }
}
