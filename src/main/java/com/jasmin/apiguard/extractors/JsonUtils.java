package com.jasmin.apiguard.extractors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

public class JsonUtils {
    private static final ObjectMapper M = new ObjectMapper();

    public static String toJson(Object value) {
        if (value == null) return null;
        try {
            return (value instanceof String s) ? s : M.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            return String.valueOf(value);
        }
    }

    public static String toJsonTruncated(Object value, int maxBytes) {
        String s = toJson(value);
        if (s == null) return null;
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (b.length <= maxBytes) return s;
        int limit = Math.max(0, maxBytes - 3);
        return new String(b, 0, limit, StandardCharsets.UTF_8) + "...";
    }
}