FROM neo4j:latest

RUN apk update && apk add \
        git maven openjdk8
WORKDIR /root
RUN git clone https://github.com/neo4j-graphql/neo4j-graphql
RUN cd neo4j-graphql && \
        mvn clean package
WORKDIR /var/lib/neo4j
RUN cp /root/neo4j-graphql/target/neo4j-graphql-3.3.0.2.jar plugins/
RUN echo 'dbms.unmanaged_extension_classes=org.neo4j.graphql=/graphql' >> conf/neo4j.conf
