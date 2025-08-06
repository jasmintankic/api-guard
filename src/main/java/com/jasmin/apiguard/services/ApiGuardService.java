package com.jasmin.apiguard.services;

import com.jasmin.apiguard.engine.DetectionEngine;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ApiGuardService {
    private final DetectionEngine detectionEngine;
    private final SecurityEventStreamService securityEventStreamService;
    private final SecurityAlertPublisher securityAlertPublisher;
    private final PreCheckService preCheckService;

    public DetectionVerdict check(SecurityEvent event) {
        DetectionVerdict preCheckVerdict = preCheckService.preCheck(event);

        if (preCheckVerdict != null) {
            securityEventStreamService.publishEvent(event, preCheckVerdict);
            securityAlertPublisher.publishAlert(event, preCheckVerdict);
            return preCheckVerdict;
        }

        DetectionVerdict verdict = detectionEngine.processEvent(event);

        securityEventStreamService.publishEvent(event, verdict);

        if (!verdict.getThreats().isEmpty()) {
            securityAlertPublisher.publishAlert(event, verdict);
        }

        return verdict;
    }
}
