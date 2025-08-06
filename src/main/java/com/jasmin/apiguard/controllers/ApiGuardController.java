package com.jasmin.apiguard.controllers;

import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.jasmin.apiguard.services.ApiGuardService;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api-guard-event")
public class ApiGuardController {
    private final ApiGuardService apiGuardService;

    @PostMapping
    public ResponseEntity<DetectionVerdict> processEvent(@RequestBody SecurityEvent event) {
        return ResponseEntity.ok(apiGuardService.check(event));
    }
}