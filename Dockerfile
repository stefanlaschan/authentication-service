# Multi-stage Dockerfile for Spring Boot (Gradle) with Amazon Corretto 21

# ====== Build stage ======
FROM gradle:8.10.2-jdk21-alpine AS builder

WORKDIR /app

# Only copy Gradle wrapper and build files first for better layer caching
COPY build.gradle settings.gradle .
COPY gradle gradle
COPY gradlew .

# Download dependencies (will be cached unless build files change)
RUN ./gradlew --no-daemon dependencies || true

# Now copy the rest of the source and build the boot jar
COPY . .
RUN ./gradlew --no-daemon clean bootJar

# ====== Runtime stage ======
FROM amazoncorretto:21-alpine

WORKDIR /app

# Copy the boot jar from the builder image
COPY --from=builder /app/build/libs/*.jar app.jar

# Expose Spring Boot default port
EXPOSE 8080

# Use the Corretto 21 JVM to run the app
ENTRYPOINT ["java","-jar","/app/app.jar"]
