FROM quay.io/quarkus/quarkus-micro-image:2-jdk-21
COPY target/*-runner.jar /app/app.jar
CMD ["java","-jar","/app/app.jar"]
