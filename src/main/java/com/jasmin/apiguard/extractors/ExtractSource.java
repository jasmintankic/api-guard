package com.jasmin.apiguard.extractors;

public enum ExtractSource {
    QUERY,         // Extract from query parameters
    HEADER,        // Extract from HTTP headers
    BODY_JSON,     // Extract from JSON body
    BODY_FORM,     // Extract from form data in the body
    PATH_VARIABLE; // Extract from path variables
}