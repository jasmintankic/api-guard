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

    public DetectionVerdict check(SecurityEvent event) {
        DetectionVerdict verdict = detectionEngine.processEvent(event);

        return verdict;
    }
}
