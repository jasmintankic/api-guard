package com.jasmin.apiguard.detectors;

import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;

import java.util.Optional;

public interface Detector {
    Optional<DetectionVerdict> detect(SecurityEvent event);
}
