#!/bin/sh

docker run \
    -d \
    -p 127.0.0.1:5432:5432 \
    -e POSTGRES_PASSWORd="secret" \
    --name oswatcher_db \
    oswatcher_db
