package com.jasmin.apiguard.detectors.bruteforcedetector;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum BruteForceScope {
    USERNAME("username"),
    IP("ip"),
    USER_IP("userip");

    final String id;
}