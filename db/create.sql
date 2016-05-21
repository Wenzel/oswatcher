CREATE DATABASE oswatcher;
\c oswatcher;

CREATE TABLE filesystem
(
    id      serial  primary key,
    path    integer[],
    name    text
);
