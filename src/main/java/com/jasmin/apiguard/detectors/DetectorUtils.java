package com.jasmin.apiguard.detectors;

import com.jasmin.apiguard.models.SecurityEvent;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class DetectorUtils {
    private static final DateTimeFormatter BUCKET_FMT = DateTimeFormatter.ofPattern("yyyyMMddHHmm");

    /**
     * Checks whether the given security event represents a login attempt.
     * Compares the action string (case-insensitive) to "login".
     */
    public static boolean isLoginAttempt(SecurityEvent e) {
        return StringUtils.hasText(e.getUsername()) && StringUtils.hasText(e.getIp());
    }

    /** First non-empty string from arguments; returns "unknown" if all empty/null. */
    public static String firstNonEmpty(String... vals) {
        for (String v : vals) if (v != null && !v.isBlank()) return v;
        return "unknown";
    }

    /**
     * Returns a non-null, non-blank string.
     * If the input is null or blank, returns "unknown".
     */
    public static String nullSafe(String s) {
        return (s == null || s.isBlank()) ? "unknown" : s;
    }

    /**
     * Normalizes a value for consistent storage and comparison.
     * Converts to lower-case using a fixed locale.
     */
    public static String normalizeValue(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.toLowerCase(Locale.ROOT);
    }

    /**
     * Converts the timestamp to epoch minutes (UTC).
     * Useful for aligning into time buckets.
     */
    public static long toEpochMinute(Instant e) {
        return e.atZone(ZoneOffset.UTC).toEpochSecond() / 60;
    }

    /**
     * Formats a bucket ID string for the given epoch minute and bucket size in minutes.
     * Aligns the minute to the nearest bucket boundary and formats as yyyyMMddHHmm.
     */
    public static String formatBucketId(long epochMinute, int bucketMinutes) {
        long aligned = (epochMinute / bucketMinutes) * bucketMinutes;
        return LocalDateTime.ofEpochSecond(aligned * 60, 0, ZoneOffset.UTC).format(BUCKET_FMT);
    }

    /**
     * Returns a lowercased copy of the input using {@link Locale#ROOT}.
     * <p>
     * If {@code s} is {@code null} or blank (only whitespace), returns the empty string.
     *
     * @param s the input string
     * @return a lowercase string, or {@code ""} if input is {@code null} or blank
     */
    public static String safeLower(String s) {
        return (s == null || s.isBlank()) ? "" : s.toLowerCase(Locale.ROOT);
    }

    /** Never-null string. */
    public static String getValueOrEmptyString(String s) {
        return (s == null) ? "" : s;
    }

    /**
     * Returns the first <em>non-blank</em> value of the first header whose name matches
     * (case-insensitive) any of the provided {@code names}, in the order they are given.
     * <p>
     * If {@code e}, its headers, {@code names}, or all candidate values are missing/blank,
     * returns the empty string.
     *
     * @param e     the security event containing headers
     * @param names candidate header names to check, in priority order
     * @return the first non-blank header value (trimmed), or {@code ""} if none
     */
    public static String firstHeaderMatch(SecurityEvent e, List<String> names) {
        if (e == null || e.getHeaders() == null || names == null || names.isEmpty()) {
            return "";
        }

        // Build a case-insensitive lookup once to avoid nested O(n*m) scans.
        Map<String, List<String>> lookup = toCaseInsensitiveLookup(e.getHeaders());

        for (String name : names) {
            if (name == null || name.isBlank()) {
                continue;
            }

            List<String> vals = lookup.get(name.toLowerCase(Locale.ROOT));

            String v = firstNonBlankTrimmed(vals);

            if (!v.isEmpty()) {
                return v; // only return if we found a non-blank value
            }
        }
        return "";
    }

    public static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode());
        }
    }


    private static Map<String, List<String>> toCaseInsensitiveLookup(Map<String, List<String>> headers) {
        Map<String, List<String>> out = new HashMap<>(Math.max(16, headers.size()));
        for (Map.Entry<String, List<String>> en : headers.entrySet()) {
            String k = en.getKey();
            if (k == null) continue;
            out.put(k.toLowerCase(Locale.ROOT), en.getValue());
        }
        return out;
    }

    private static String firstNonBlankTrimmed(List<String> vals) {
        if (vals == null || vals.isEmpty()) return "";
        for (String v : vals) {
            if (v != null && !v.isBlank()) return v.trim();
        }
        return "";
    }

    public static List<String> windowKeys(String namespace, String id, long epochMinute, int bucketsToSum, int bucketInMinutes) {
        return IntStream.range(0, bucketsToSum)
                .mapToObj(i -> DetectorUtils.formatBucketId(epochMinute - (long) i * bucketInMinutes, bucketInMinutes))
                .map(bucketId -> namespace + ":" + id + ":" + bucketId)
                .collect(Collectors.toList());
    }

    public static long sumBuckets(List<String> vals) {
        long sum = 0L;

        if (vals == null) {
            return 0L;
        }

        for (String v : vals) {
            if (v != null && !v.isEmpty()) {
                try {
                    sum += Long.parseLong(v);
                } catch (NumberFormatException ignored) {}
            }
        }
        return sum;
    }
}
