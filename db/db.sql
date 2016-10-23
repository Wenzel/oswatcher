-- MySQL Workbench Forward Engineering

-- -----------------------------------------------------
-- Schema oswatcher
-- -----------------------------------------------------
CREATE DATABASE oswatcher;
\c oswatcher

-- -----------------------------------------------------
-- Table os
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS os (
  id SERIAL,
  name TEXT NOT NULL,
  PRIMARY KEY (id));


-- -----------------------------------------------------
-- Table filesystem
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS filesystem (
  os_id SERIAL,
  inode BIGINT NOT NULL,
  path INTEGER[] NOT NULL,
  filename TEXT NOT NULL,
  PRIMARY KEY (os_id, inode),
  CONSTRAINT fk_filesystem_vm
    FOREIGN KEY (os_id)
    REFERENCES os (id)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION);


-- -----------------------------------------------------
-- Table inode
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS inode (
  os_id SERIAL,
  fs_inode BIGINT NOT NULL,
  PRIMARY KEY (os_id, fs_inode),
  CONSTRAINT fk_inode_filesystem1
    FOREIGN KEY (os_id , fs_inode)
    REFERENCES filesystem (os_id , inode)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION);

