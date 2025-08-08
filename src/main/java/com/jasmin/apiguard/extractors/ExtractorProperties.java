package com.jasmin.apiguard.extractors;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "extractors")
public class ExtractorProperties {
    private Map<String, List<ExtractRule>> rules;
}
