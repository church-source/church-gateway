FROM gradle:5.5.1-jdk8 AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon -DskipTests

FROM openjdk:8-jre-slim

EXPOSE 9090

RUN mkdir /app

COPY --from=build /home/gradle/src/build/libs/*.jar /app/church-gateway.jar

ENV JAVA_OPTS="-XX:+UseSerialGC -Xss512k -XX:MaxRAM=72m -XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap "

ENTRYPOINT ["sh","-c","java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /app/church-gateway.jar"]
