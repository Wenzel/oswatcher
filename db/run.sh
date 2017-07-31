#!/bin/sh

PASSWORD="admin"

# password needs to be changed after neo4j 3.0
# a limit of 40000 fd opened is recommended

docker run \
    --detach \
    --publish=7474:7474 --publish=7687:7687 \
    --env NEO4J_AUTH="neo4j/${PASSWORD}" \
    --ulimit=nofile=40000:40000 \
    --name oswatcher_db \
    neo4j
