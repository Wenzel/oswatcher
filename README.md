# OSWatcher

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

# Setup

~~~
virtualenv --system-site-packages -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
~~~

Note: We have to use `--system-site-packages` because `libguestfs` is not
available on `pip`.

## Neo4j database

`OSWatcher`'s data is stored on a `neo4j` database.

Follow the instructions in the `db` directory to run a it inside a docker
container.

# Usage

~~~
(venv) $ python -m oswatcher.capture <vm_name> hooks.json
~~~

Example: ![Capturing ubuntu
filesystem](https://user-images.githubusercontent.com/964610/47535862-14ddbb00-d8c6-11e8-88cd-efa5db339bb8.jpg)

Access `Neo4j` web interface at `http://localhost:7474` ![ubuntu etc
neo4j](https://user-images.githubusercontent.com/964610/47535864-18714200-d8c6-11e8-885b-27d17c8d6235.png)

## neo4j

~~~
MATCH(n)
RETURN(n)
LIMIT 300;
~~~

# Troubleshooting

## libguestfs

If `libguestfs` fails to initialize, you can use the `libguestfs-test-tool` to
quickly understand the root cause of the failure.
