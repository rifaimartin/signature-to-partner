#MAVEN BUILD
FROM maven:3.5.2-jdk-8-alpine AS MAVEN_TOOL_CHAIN
COPY pom.xml /tmp/
COPY src /tmp/src/
WORKDIR /tmp/
RUN mvn package -Dmaven.test.skip=true

FROM openjdk:8-jdk-alpine
RUN apk add ttf-dejavu
ARG JAR_FILE=target/*.jar
ARG JAR_NAME=czdbs-be.jar
COPY --from=MAVEN_TOOL_CHAIN /tmp/${JAR_FILE} ${JAR_NAME}
ENTRYPOINT ["java","-jar","czdbs-be.jar"]