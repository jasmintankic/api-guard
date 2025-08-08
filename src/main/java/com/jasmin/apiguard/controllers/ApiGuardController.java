package com.jasmin.apiguard.controllers;

import com.jasmin.apiguard.extractors.ExtractUtils;
import lombok.RequiredArgsConstructor;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import com.jasmin.apiguard.services.ApiGuardService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;

@RequiredArgsConstructor
@RestController
public class ApiGuardController {

    private final ApiGuardService apiGuardService;
    private final ExtractUtils extractUtils;

    @RequestMapping(
            value = "/**",
            method = {
                    RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
                    RequestMethod.DELETE, RequestMethod.PATCH, RequestMethod.HEAD,
                    RequestMethod.OPTIONS, RequestMethod.TRACE
            },
            consumes = MediaType.ALL_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<DetectionVerdict> catchAll(
            HttpServletRequest request,
            @RequestHeader MultiValueMap<String, String> headers,
            @RequestParam MultiValueMap<String, String> queryParams,
            @RequestBody(required = false) byte[] body
    ) {
        SecurityEvent event = SecurityEvent.builder()
                .method(request.getMethod())
                .path(request.getRequestURI())        // full path that was called
                .queryParams(queryParams)             // all query params (multi-valued)
                .headers(headers)                     // all headers (multi-valued)
                .remoteAddr(request.getRemoteAddr())
                .contentType(request.getContentType())
                .body(body)
                .timestamp(Instant.now())
                .username(extractUtils.getProperty("username", headers, queryParams, body))// may be null / empty
                .ip(extractUtils.getProperty("client-ip", headers, queryParams, body))
                .userAgent(extractUtils.getProperty("user-agent", headers, queryParams, body))
                .correlationId(extractUtils.getProperty("correlation-id", headers, queryParams, body))
                .build();

        return ResponseEntity.ok(apiGuardService.check(event));
    }
}
