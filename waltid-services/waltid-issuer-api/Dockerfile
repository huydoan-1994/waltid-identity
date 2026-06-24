# NOTE: Prefer Gradle Ktor/Jib tasks (publishImageToLocalRegistry/publishImage) for builds.
# This Dockerfile is for manual/custom Docker workflows.
# Uses Eclipse Temurin JDK 21 + Gradle Wrapper (pinned in gradle-wrapper.properties)
# to avoid version incompatibilities with Android Gradle Plugin.

FROM eclipse-temurin:21-jdk AS pre-cache
COPY . /home/src
COPY gradle.properties settings.gradle.kts /home/app/
COPY build-logic /home/app/build-logic
COPY gradle /home/app/gradle
COPY gradlew /home/app/gradlew
RUN chmod +x /home/app/gradlew
RUN cd /home/src && \
    find . -name "build.gradle.kts" -exec sh -c 'mkdir -p /home/app/$(dirname "$1"); cp "$1" /home/app/$1' _ {} \;

# Stage 1: Cache Gradle dependencies
FROM eclipse-temurin:21-jdk AS cache
RUN mkdir -p /home/gradle/cache_home
ENV GRADLE_USER_HOME=/home/gradle/cache_home
COPY --from=pre-cache /home/app/ /home/gradle/app/
WORKDIR /home/gradle/app/waltid-services/waltid-issuer-api
RUN ../../gradlew dependencies --no-daemon

# Stage 2: Build Application
FROM eclipse-temurin:21-jdk AS build
COPY --from=cache /home/gradle/cache_home /home/gradle/.gradle
COPY . /home/gradle/src
RUN chmod +x /home/gradle/src/gradlew
WORKDIR /home/gradle/src/waltid-services/waltid-issuer-api
RUN ../../gradlew buildFatJar --no-daemon

# Stage 3: Create the Runtime Image
FROM amazoncorretto:22 AS runtime
WORKDIR /waltid-issuer-api

# Create an unprivileged user and group
RUN yum install -y shadow-utils \
 && groupadd -r app \
 && useradd -r -g app -u 10001 app \
 && yum clean all

COPY --chown=app:app --from=build \
  /home/gradle/src/waltid-services/waltid-issuer-api/build/libs/*.jar \
  /waltid-issuer-api/issuer-api.jar

USER app
EXPOSE 7002
ENTRYPOINT ["java","-jar","/waltid-issuer-api/issuer-api.jar"]
