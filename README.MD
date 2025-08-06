# Real-Time API Abuse Detection Engine with Spring Boot and Redis

## 🚀 What Is this Project?

This project is a **real-time API Abuse Detection Engine** built using Spring Boot and Redis.  
It offers plug-and-play detection of brute-force logins, enumeration attacks, IP/device abuse and replay attacks returning threat verdicts in milliseconds.

Redis is the real-time backbone here, going far beyond just caching. All detection logic, analytics, alerting, and dashboards are powered by Redis.

---

## 🧩 Features

- **Real-time threat detection:**
    - Brute-force attacks
    - Enumeration attacks
    - IP abuse 
    - Device/Browser abuse
    - Replay attacks
- **“Bad actor” buckets:** Fast blocklists for IPs, usernames, fingerprints, etc.
- **Instant event and threat analytics:**
    - By date and time range
    - By threat type
- **Event sourcing:** Full audit/replay using Redis Streams.
- **Live alerts:** Pub/Sub notifications on threat detection.

---

## ❤️ Why Redis Is the Star

Redis isn’t just a cache here, it’s the primary security database and event engine:

- **Primary real-time database:** All security state lives in Redis for sub-millisecond access and safe, atomic updates.
- **Sets for bad actors:** Instantly block or escalate known offenders.
- **Time-bucketed counters:** Lightning-fast analytics—“How many login attempts (and threats) in the last hour?”
- **Streams:** Every event and detection verdict is recorded for forensics, dashboards, and ML analytics.
- **Pub/Sub:** Real-time notification and automation.
- **Atomicity & expiry:** No manual cleanup needed, rolling windows “just work”.

**Redis powers the whole system.**

---

## ⚡ How It Works

- **POST** to `/api/api-guard-event` with each API or security action.
    - Detection engine checks for abuse patterns and returns a verdict.
    - Events and threats are logged in Redis (counters, sets, streams).
    - Bad actors are instantly recognized and can be blocked in O(1) time.
    - Alerts are published to Redis Pub/Sub channels for instant response.

- **GET** from `/api/api-guard-analytics/event-count?from=2025-08-06T01:12:00&to=2025-08-06T01:20:00`
    - Returns event and threat counts, plus breakdown by threat type, for any date/time range.

---

## 🔥 What Redis Powers Here

- **Brute-force:** `INCR` per minute, per user/IP—automatic rolling window.
- **Enumeration:** `SADD` endpoints per IP per minute—instant detection of scanning.
- **Replay:** `SETNX` for actions—single-use or reject instantly.
- **Bad actors:** `SISMEMBER` for known-bad—always O(1) lookup.
- **Analytics:** Aggregate keys like `events:2026-12-21:10:05` for constant-time stats.
- **Live streams:** `XADD` for every event—replay or analyze any time.
- **Alerts:** `PUBLISH` on detection—trigger bots, dashboards, or SIEMs.

---

## 🛠️ Quick Start

**Prerequisites:**
- Java 17+
- Redis 8+ (locally or Docker)
