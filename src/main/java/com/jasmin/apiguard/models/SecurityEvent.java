package com.jasmin.apiguard.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SecurityEvent {
    private String ip;
    private String username;
    private String deviceFingerprint;
    private String action;
    private String status;
    private String endpoint;
    private String correlationId;

    @JsonIgnore
    private Instant timestamp = Instant.now();
}