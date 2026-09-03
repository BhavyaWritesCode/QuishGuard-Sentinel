# Stage 1 — Build
FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn clean package -DskipTests -q

# Stage 2 — Run
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

RUN addgroup --system quishguard && adduser --system --ingroup quishguard quishguard
USER quishguard

COPY --from=builder /app/target/sentinel-1.0.0-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]