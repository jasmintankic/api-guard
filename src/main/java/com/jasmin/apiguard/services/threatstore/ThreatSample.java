package com.jasmin.apiguard.services.threatstore;

import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
public class ThreatSample {
    private String id;
    private Instant at;
    private String method;
    private String url;
    private String ua;
    private List<String> threats;
    private List<String> recommendations;
    private Object headers;
    private String bodyB64;
    private String corrId;
}