package com.jasmin.apiguard.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DetectionVerdict {
    private List<String> threats;
    private List<String> recommendations;
    private String details;
}
