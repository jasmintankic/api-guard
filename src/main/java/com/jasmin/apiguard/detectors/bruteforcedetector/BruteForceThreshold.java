package com.jasmin.apiguard.detectors.bruteforcedetector;

import jakarta.validation.constraints.Min;
import lombok.Data;

@Data
public class BruteForceThreshold {
    /** Per-username allowed failures within window. */
    @Min(1)
    private int username = 5;

    /** Per-IP allowed failures within window. */
    @Min(1)
    private int ip = 20;

    /** Per username+IP allowed failures within window. */
    @Min(1)
    private int userIp = 4;
}
