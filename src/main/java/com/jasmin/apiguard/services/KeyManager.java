package com.jasmin.apiguard.services;

public class KeyManager {
    public static String MALICIOUS_IP_BUCKET = "threat:ips";
    public static String MALICIOUS_USERNAMES_BUCKET = "threat:usernames";
    public static String MALICIOUS_FINGERPRINT_BUCKET = "threat:fingerprints";
    public static String MALICIOUS_CORRELATION_ID_BUCKET = "threat:correlations";

    public static final String ACCOUNT_TAKEOVER_RISK = "ACCOUNT_TAKEOVER_RISK"; // optional alt
    public static final String MALICIOUS_DEVICE_BUCKET = "malicious:device";
    public static final String MALICIOUS_USERNAME_BUCKET = "malicious:username";

    public static String getThreatsKey(String minuteKey) {
        return "threats:" + minuteKey;
    }

    public static String getEventsKey(String minuteKey) {
        return "events:" + minuteKey;
    }
}
