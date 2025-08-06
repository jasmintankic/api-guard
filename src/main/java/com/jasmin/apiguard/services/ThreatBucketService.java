package com.jasmin.apiguard.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatBucketService {

    private final StringRedisTemplate redisTemplate;

    public void addToBucket(String bucket, String value) {
        try {
            redisTemplate.opsForSet().add(bucket, value);
        } catch (Exception e) {
            log.error("Error adding to bucket: {} {}", bucket, value, e);
        }
    }

    public boolean isInBucket(String bucket, String value) {
        try {
            Boolean exists = redisTemplate.opsForSet().isMember(bucket, value);
            return Boolean.TRUE.equals(exists);
        } catch (Exception e) {
            log.error("Error checking if in bucket: {} {}", bucket, value, e);
            return false;
        }
    }

    public void removeFromBucket(String bucket, String value) {
        try {
            redisTemplate.opsForSet().remove(bucket, value);
        } catch (Exception e) {
            log.error("Error removing from bucket: {} {}", bucket, value, e);
        }
    }
}
