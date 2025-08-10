package com.jasmin.apiguard.extractors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedCaseInsensitiveMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
@RequiredArgsConstructor
public class ExtractUtils {

    private final ExtractorProperties config;
    private static final ObjectMapper OM = new ObjectMapper();

    public String getProperty(
            String propertyName,
            MultiValueMap<String, String> headers,
            MultiValueMap<String, String> queryParams,
            byte[] body
    ) {
        List<ExtractRule> rules = config.getRules().getOrDefault(propertyName, Collections.emptyList());
        if (rules.isEmpty()) {
            return null;
        }

        Map<String, List<String>> ciHeaders = new LinkedCaseInsensitiveMap<>();
        headers.forEach(ciHeaders::put);

        Map<String, Object> bodyJson = null;
        Map<String, List<String>> bodyForm = null;

        for (ExtractRule rule : rules) {
            String val = null;

            switch (rule.getSource()) {
                case ExtractSource.HEADER -> val = first(ciHeaders.get(rule.getKey()));
                case ExtractSource.BODY_JSON -> {
                    if (bodyJson == null) bodyJson = parseJson(body);
                    if (bodyJson != null && bodyJson.containsKey(rule.getKey())) {
                        val = Objects.toString(bodyJson.get(rule.getKey()), null);
                    }
                }
                case BODY_FORM -> {
                    if (bodyForm == null) bodyForm = parseForm(body);
                    val = first(bodyForm.get(rule.getKey()));
                }
                case ExtractSource.QUERY -> val = first(queryParams.get(rule.getKey()));
            }

            if (val != null && !val.isBlank()) return val.trim();
        }
        return null;
    }

    // helpers
    private static String first(List<String> list) {
        if (list == null) return null;
        for (String v : list) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static Map<String, Object> parseJson(byte[] body) {
        if (body == null || body.length == 0) return null;
        try { return OM.readValue(body, new TypeReference<>() {}); }
        catch (Exception e) { return null; }
    }

    private static Map<String, List<String>> parseForm(byte[] body) {
        if (body == null || body.length == 0) return null;
        Map<String, List<String>> map = new LinkedHashMap<>();
        String s = new String(body, StandardCharsets.UTF_8);
        for (String pair : s.split("&")) {
            String[] kv = pair.split("=", 2);
            String k = kv[0];
            String v = kv.length > 1 ? kv[1] : "";
            map.computeIfAbsent(k, _k -> new ArrayList<>()).add(v);
        }
        return map;
    }
}
