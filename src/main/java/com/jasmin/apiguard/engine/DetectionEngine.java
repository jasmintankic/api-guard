package com.jasmin.apiguard.engine;

import com.jasmin.apiguard.detectors.Detector;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class DetectionEngine {
    private final List<Detector> detectors;

    public DetectionVerdict processEvent(SecurityEvent event) {
        List<String> threats = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        StringBuilder details = new StringBuilder();

        for (Detector detector : detectors) {
            Optional<DetectionVerdict> verdict = detector.detect(event);
            verdict.ifPresent(v -> {
                threats.addAll(v.getThreats());
                recommendations.addAll(v.getRecommendations());
                if (v.getDetails() != null) details.append(v.getDetails()).append(" ");
            });
        }
        return new DetectionVerdict(threats, recommendations, details.toString().trim());
    }
}