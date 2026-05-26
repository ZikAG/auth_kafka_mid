# ============================================================
# Stage 1: Build the fat JAR with Maven
# ============================================================
FROM maven:3.9.7-eclipse-temurin-17-alpine AS builder

WORKDIR /build

# Copy the POM first so Maven can download dependencies independently
# of source changes (layer caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build the fat jar (assembly:single is bound to package phase)
COPY src/ src/
RUN mvn clean package -DskipTests -B

# ============================================================
# Stage 2: Minimal image that acts as an init-container
#          to copy the plugin JAR onto a shared volume
# ============================================================
FROM alpine:3.19

LABEL maintainer="kafka-oauth-plugins"
LABEL description="Init container that copies the Kafka OAuth plugin JAR to a shared volume"
LABEL version="1.0.0"

# Copy the assembled fat jar from the builder stage
COPY --from=builder \
     /build/target/kafka-oauth-plugins-*-jar-with-dependencies.jar \
     /app/kafka-oauth-plugins.jar

# The init container is expected to run with a volume mounted at /plugins.
# It copies the JAR into that volume so the Kafka broker container can
# pick it up at startup via the plugin.path broker property.
CMD ["cp", "/app/kafka-oauth-plugins.jar", "/plugins/kafka-oauth-plugins.jar"]
