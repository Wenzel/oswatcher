# OSWatcher

[![Join the chat at https://gitter.im/kvm-vmi/Lobby](https://badges.gitter.im/trailofbits/algo.svg)](https://gitter.im/oswatcher/Lobby)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![Build Status](https://travis-ci.org/Wenzel/oswatcher.svg?branch=master)](https://travis-ci.org/Wenzel/oswatcher)

> Track the evolution of operating systems over time

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
 - [Troubleshooting](#troubleshooting)
 - [Maintainers](#maintainers)
 - [Contributing](#contributing)
 - [License](#license)

# Overview

OSWatcher is an ambitious project that aims to track the evolution of operating
systems by making `diffs` between recognizable characteristics.

The core of `OSWatcher` is to build a reference database about every OS
releases, that is to be populated by an `extractor` in charge of capturing the
various information that can be extracted from an installed operating system, both online
and offline, in a reproducible way.

Offline:

- filesystem hierarchy
- setuid binaries
- executable properties
- library graph dependencies
- statistics around `perl/sh/python` scripts
- syscall tables
- kernel configuration
- cronjobs
- `/etc` configuration

Online:

- IDLE memory consumption
- default processes running
- mapped libraries
- listening ports and associated services
- DNS requests sent
- unix sockets
- dbus traffic
- iptables rules
- loaded drivers

# Requirements

- `Docker`
- `libguestfs`
- `python3`
- `virtualenv`

## Install

~~~
virtualenv --system-site-packages -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
~~~

Note: We have to use `--system-site-packages` because `libguestfs` is not
available on `pip`.

### Neo4j database

`OSWatcher`'s data is stored on a `neo4j` database.

Follow the instructions in the `db` directory to run a it inside a docker
container.

## Usage

The VM name will be searched via `Libvirt`.

~~~
(venv) $ python -m oswatcher <vm_name> hooks.json
~~~

Example: ![Capturing ubuntu
filesystem](https://user-images.githubusercontent.com/964610/47535862-14ddbb00-d8c6-11e8-88cd-efa5db339bb8.jpg)

Access `Neo4j` web interface at `http://localhost:7474` ![ubuntu etc
neo4j](https://user-images.githubusercontent.com/964610/47535864-18714200-d8c6-11e8-885b-27d17c8d6235.png)

### neo4j

~~~
MATCH(n)
RETURN(n)
LIMIT 300;
~~~

## Troubleshooting

### libguestfs

If `libguestfs` fails to initialize, you can use the `libguestfs-test-tool` to
quickly understand the root cause of the failure.

## Maintainers

[@Wenzel](https://github.com/Wenzel)

## Contributing

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[GNU General Public License v3.0](https://github.com/Wenzel/oswatcher/blob/master/LICENSE)
