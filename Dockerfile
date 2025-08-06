# ---- Stage 1: Build ----
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /build

# Copy Gradle files and source first (for layer caching)
COPY build.gradle settings.gradle gradle.properties* gradlew ./
COPY gradle ./gradle

# Copy the rest of the source code
COPY src ./src

# Build the fat JAR (change 'bootJar' if needed for plain Jar)
RUN ./gradlew bootJar --no-daemon

# ---- Stage 2: Runtime ----
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy the fat JAR from builder stage
COPY --from=builder /build/build/libs/*.jar app.jar

EXPOSE 8080

# JVM options and config location are overridable via env variables
ENTRYPOINT ["java", "-jar", "app.jar"]
