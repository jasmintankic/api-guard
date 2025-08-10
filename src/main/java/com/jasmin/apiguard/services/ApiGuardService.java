package com.jasmin.apiguard.services;

import com.jasmin.apiguard.engine.DetectionEngine;
import com.jasmin.apiguard.services.threatstore.ThreatStoreService;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ApiGuardService {
    private final DetectionEngine detectionEngine;
    private final ThreatStoreService threatStoreService;

    public DetectionVerdict check(SecurityEvent event) {
        DetectionVerdict verdict = detectionEngine.processEvent(event);
        if (verdict != null && verdict.getThreats() != null && !verdict.getThreats().isEmpty()) {
            threatStoreService.save(event, verdict);
        }
        return verdict;
    }
}
