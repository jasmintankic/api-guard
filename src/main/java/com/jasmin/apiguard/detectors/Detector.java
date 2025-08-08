package com.jasmin.apiguard.detectors;

import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.util.StringUtils;

import java.util.Optional;

public interface Detector {
    Optional<DetectionVerdict> detect(SecurityEvent event);

    /**
     * Checks whether the given security event represents a login attempt.
     * Compares the action string (case-insensitive) to "login".
     */
    default boolean isLoginAttempt(SecurityEvent e) {
        return StringUtils.hasText(e.getUsername()) && StringUtils.hasText(e.getIp());
    }

    /** First non-empty string from arguments; returns "unknown" if all empty/null. */
    default String firstNonEmpty(String... vals) {
        for (String v : vals) if (v != null && !v.isBlank()) return v;
        return "unknown";
    }
}
