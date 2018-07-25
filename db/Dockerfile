FROM neo4j:latest

RUN wget -q 'https://github.com/neo4j-graphql/neo4j-graphql/releases/download/3.4.0.1/neo4j-graphql-3.4.0.1.jar' -P plugins/
RUN echo 'dbms.unmanaged_extension_classes=org.neo4j.graphql=/graphql' >> conf/neo4j.conf
