package com.jasmin.apiguard.detectors.ddosattackdetector;

import com.jasmin.apiguard.detectors.Detector;
import com.jasmin.apiguard.models.DetectionVerdict;
import com.jasmin.apiguard.models.SecurityEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class DdosDetector implements Detector {

    private final StringRedisTemplate redis;
    private final DdosDetectorProperties props;

    // Built-in path normalization patterns (UUIDs, numeric IDs)
    private static final List<Pattern> NORMALIZE_PATTERNS = List.of(
            Pattern.compile("/[0-9a-fA-F-]{36}(?=/|$)"),  // UUID
            Pattern.compile("/[0-9]{2,}(?=/|$)")          // numeric IDs
    );

    public Optional<DetectionVerdict> detect(SecurityEvent e) {
        if (!props.isEnabled()) return Optional.empty();

        final String clientIp = extractClientIp(e);
        final String normPath = normalizePath(Objects.requireNonNullElse(e.getPath(), "/"));
        final String pfx = props.getKeyPrefix();

        final String ipS1Key  = pfx + ":ip:" + clientIp + ":s1";
        final String ipS10Key = pfx + ":ip:" + clientIp + ":s10";
        final String gS1Key   = pfx + ":global:s1";
        final String gS10Key  = pfx + ":global:s10";
        final String pS10Key  = pfx + ":path:" + Integer.toHexString(normPath.hashCode()) + ":s10";
        final String uniqKey  = pfx + ":uniq:m" + (System.currentTimeMillis() / 60000);

        List<Object> exec = processRateLimitMetrics(ipS1Key, ipS10Key, gS1Key, gS10Key, pS10Key, uniqKey, clientIp);

        int tailOffset = props.isSignalsUseDistinctIpSurge() ? 6 : 5;
        int n = exec.size();
        long ipS1  = parseLong(exec.get(n - tailOffset));
        long ipS10 = parseLong(exec.get(n - tailOffset + 1));
        long gS1   = parseLong(exec.get(n - tailOffset + 2));
        long gS10  = parseLong(exec.get(n - tailOffset + 3));
        long pS10  = parseLong(exec.get(n - tailOffset + 4));
        long uniq  = props.isSignalsUseDistinctIpSurge() ? parseLong(exec.get(n - 1)) : -1;

        boolean ipBurst   = (ipS1  > props.getThresholdsPerIpS1())
                         || (ipS10 > props.getThresholdsPerIpS10());
        boolean globSpike = (gS1   > props.getThresholdsGlobalS1())
                         || (gS10  > props.getThresholdsGlobalS10());
        boolean pathSpike = (pS10  > props.getThresholdsPerPathS10());
        boolean uniqSpike = props.isSignalsUseDistinctIpSurge() && (uniq > props.getThresholdsUniqIpsPerMinute());

        List<String> threats = new ArrayList<>();
        List<String> recs = new ArrayList<>();
        StringBuilder details = new StringBuilder();

        if (ipBurst) {
            threats.add("PER_IP_RATE_LIMIT_EXCEEDED");
            recs.add("Throttle or temporarily block IP " + clientIp);
            details.append(String.format("ip[%s] s1=%d s10=%d > (%d,%d). ", clientIp, ipS1, ipS10, props.getThresholdsPerIpS1(), props.getThresholdsPerIpS10()));
        }
        if (globSpike) {
            threats.add("GLOBAL_TRAFFIC_SPIKE");
            recs.add("Enable global shed (429/503), scale edge protections");
            details.append(String.format("global s1=%d s10=%d > (%d,%d). ", gS1, gS10, props.getThresholdsGlobalS1(), props.getThresholdsGlobalS10()));
        }
        if (pathSpike) {
            threats.add("HIGH_TRAFFIC_ENDPOINT");
            recs.add("Add per-path limit and cache/short-circuit handler for '" + normPath + "'");
            details.append(String.format("path[%s] s10=%d > %d. ", normPath, pS10, props.getThresholdsPerPathS10()));
        }
        if (uniqSpike) {
            threats.add("SUSPICIOUS_UNIQUE_IP_SURGE");
            recs.add("Activate CDN/WAF bot filters; require JS challenge");
            details.append(String.format("uniq/min~%d > %d. ", uniq, props.getThresholdsUniqIpsPerMinute()));
        }
        if (props.isSignalsCheckSuspiciousUa() && looksSuspiciousUA(e.getUserAgent())) {
            threats.add("SUSPICIOUS_USER_AGENT");
            recs.add("Challenge or block UA pattern");
            details.append("ua='").append(Objects.toString(e.getUserAgent(), "")).append("'. ");
        }

        if (threats.isEmpty()) {
            return Optional.empty();
        }

        var verdict = new DetectionVerdict(new ArrayList<>(new LinkedHashSet<>(threats)),
                new ArrayList<>(new LinkedHashSet<>(recs)),
                details.toString().trim());

        return Optional.of(verdict);
    }

    private List<Object> processRateLimitMetrics(String ipS1Key, String ipS10Key, String gS1Key, String gS10Key, String pS10Key, String uniqKey, String clientIp) {
        return redis.executePipelined((RedisCallback<Object>) conn -> {
            var strings = conn.stringCommands();
            var keys    = conn.keyCommands();
            var hll     = conn.hyperLogLogCommands();

            // use explicit UTF-8 like your first version (safer than platform default)
            byte[] ipS1  = ipS1Key.getBytes(StandardCharsets.UTF_8);
            byte[] ipS10 = ipS10Key.getBytes(StandardCharsets.UTF_8);
            byte[] gS1   = gS1Key.getBytes(StandardCharsets.UTF_8);
            byte[] gS10  = gS10Key.getBytes(StandardCharsets.UTF_8);
            byte[] pS10  = pS10Key.getBytes(StandardCharsets.UTF_8);
            byte[] uniq  = uniqKey.getBytes(StandardCharsets.UTF_8);
            byte[] ip    = clientIp.getBytes(StandardCharsets.UTF_8);

            // precompute TTLs as Durations
            Duration s1Ttl   = Duration.ofSeconds(props.getWindowsS1TtlSeconds());
            Duration s10Ttl  = Duration.ofSeconds(props.getWindowsS10TtlSeconds());
            Duration uniqTtl = Duration.ofSeconds(props.getWindowsUniqTtlSeconds());

            conn.multi(); // begin transaction (all commands below are queued)

            strings.incr(ipS1);   keys.expire(ipS1,  s1Ttl);
            strings.incr(ipS10);  keys.expire(ipS10, s10Ttl);
            strings.incr(gS1);    keys.expire(gS1,   s1Ttl);
            strings.incr(gS10);   keys.expire(gS10,  s10Ttl);
            strings.incr(pS10);   keys.expire(pS10,  s10Ttl);

            if (props.isSignalsUseDistinctIpSurge()) {
                hll.pfAdd(uniq, new byte[][] { ip });
                keys.expire(uniq, uniqTtl);
            }

            strings.get(ipS1);
            strings.get(ipS10);
            strings.get(gS1);
            strings.get(gS10);
            strings.get(pS10);
            if (props.isSignalsUseDistinctIpSurge()) {
                hll.pfCount(uniq);
            }

            conn.exec();   // enqueue EXEC (its reply will be the last item in the pipeline)
            return null;   // executePipelined ignores this return value; only queued ops matter
        });
    }

    // ===== Helpers =====
    private long parseLong(Object o) {
        return switch (o) {
            case null -> 0L;
            case byte[] b -> Long.parseLong(new String(b));
            case String s -> Long.parseLong(s);
            case Number n -> n.longValue();
            default -> 0L;
        };
    }

    private String normalizePath(String path) {
        String out = path;
        for (Pattern p : NORMALIZE_PATTERNS) {
            out = p.matcher(out).replaceAll("/:id");
        }
        return out;
    }

    private String extractClientIp(SecurityEvent e) {
        if (e.getHeaders() != null) {
            for (String h : props.getIpHeaders()) {
                List<String> vs = e.getHeaders().get(h);
                if (vs != null && !vs.isEmpty()) {
                    String raw = vs.getFirst();
                    String first = raw.contains(",") ? raw.split(",")[0].trim() : raw.trim();
                    if (!first.isBlank()) return stripIpv6Mapped(first);
                }
            }
        }
        if (e.getIp() != null && !e.getIp().isBlank()) return stripIpv6Mapped(e.getIp());
        if (e.getRemoteAddr() != null && !e.getRemoteAddr().isBlank()) return stripIpv6Mapped(e.getRemoteAddr());
        return "unknown";
    }

    private String stripIpv6Mapped(String ip) {
        return ip.startsWith("::ffff:") ? ip.substring(7) : ip;
    }

    private boolean looksSuspiciousUA(String ua) {
        if (ua == null || ua.isBlank()) return true;
        String l = ua.toLowerCase();
        for (String bad : props.getSuspiciousUserAgents()) {
            if (l.contains(bad.toLowerCase())) return true;
        }
        return false;
    }
}