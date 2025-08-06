package com.jasmin.apiguard.services;

public class KeyManager {
    public static String MALICIOUS_IP_BUCKET = "threat:ips";
    public static String MALICIOUS_USERNAMES_BUCKET = "threat:usernames";
    public static String MALICIOUS_FINGERPRINT_BUCKET = "threat:fingerprints";
    public static String MALICIOUS_CORRELATION_ID_BUCKET = "threat:correlations";

    public static String getThreatsKey(String minuteKey) {
        return "threats:" + minuteKey;
    }

    public static String getEventsKey(String minuteKey) {
        return "events:" + minuteKey;
    }
}
