package com.jasmin.apiguard.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SecurityEvent {
    private String method;
    private String path;
    private String remoteAddr;
    private String contentType;

    // All headers: key -> list of values
    private Map<String, List<String>> headers;

    // All query params: key -> list of values
    private Map<String, List<String>> queryParams;

    // Raw request body
    private byte[] body;

    private Instant timestamp;

    private String ip;
    private String username;
    private String userAgent;
    private String correlationId;
}