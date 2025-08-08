package com.jasmin.apiguard.extractors;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ExtractRule {
    private ExtractSource source;
    private String key;
}