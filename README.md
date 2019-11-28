# OSWatcher

[![Join the chat at https://gitter.im/kvm-vmi/Lobby](https://badges.gitter.im/trailofbits/algo.svg)](https://gitter.im/oswatcher/Lobby)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
![](https://github.com/Wenzel/oswatcher/workflows/Python%20application/badge.svg)
[![tokei](https://tokei.rs/b1/github/Wenzel/oswatcher)](https://github.com/Wenzel/oswatcher)
[![repo size](https://img.shields.io/github/repo-size/Wenzel/oswatcher)](https://github.com/Wenzel/oswatcher)

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

## Overview

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

## Requirements

- [`Docker`](https://www.docker.com/)
- `python >= 3.7`
- `virtualenv`
- [`libguestfs`](http://libguestfs.org/)

## Install

1. Clone repo and submodules

~~~
git clone https://github.com/Wenzel/oswatcher.git
cd oswatcher
git submodule update --init
~~~

2. Install system dependencies

*For `Docker` please refer to your distribution*

On `Ubuntu 18.04`

~~~
sudo apt-get install virtualenv python3-virtualenv libguestfs0 libguestfs-dev python3-guestfs python3-dev pkg-config libvirt-dev
~~~

3. Create virtualenv

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

## VM setup

OSWatcher works on VMs stored in `libvirt`, either via `qemu:///session`
or `qemu:///system`.

Note: `qemu:///session` is recommended as it requires less permission
and should work without further configuration.

The only setup required is to specify a `release_date` in `JSON` format, so that
the capture tool can insert this information in the database as well.

-> In the VM XML `<description>` field, add the following content:
~~~JSON
{"release_date": "2012-04-01"}
~~~

You can use edit `virsh edit <domain>` or `virt-manager` tool which should be easier.

## Usage

Start the capture tool on a `VM` and specify the hooks configuration.

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

### Web frontend

A web frontend developed on top of `VueJS` is available in the `web` folder

~~~
cd web
npm install
npm run dev
~~~

#### Filesystem view

![filesystem_view](https://img.linuxfr.org/img/68747470733a2f2f757365722d696d616765732e67697468756275736572636f6e74656e742e636f6d2f3936343631302f34373735393035322d38326237323738302d646362362d313165382d393733302d6330656131353738333136332e6a7067/47759052-82b72780-dcb6-11e8-9730-c0ea15783163.jpg)

#### Process list view

![process_list_view](https://img.linuxfr.org/img/68747470733a2f2f757365722d696d616765732e67697468756275736572636f6e74656e742e636f6d2f3936343631302f34373735393035382d38633430386638302d646362362d313165382d383638352d6665383464353431303462632e6a7067/47759058-8c408f80-dcb6-11e8-8685-fe84d54104bc.jpg)

#### Syscall table view

![syscall_table_view](https://img.linuxfr.org/img/68747470733a2f2f757365722d696d616765732e67697468756275736572636f6e74656e742e636f6d2f3936343631302f34373735393036312d38656132653938302d646362362d313165382d386637392d6133646132366564366261652e6a7067/47759061-8ea2e980-dcb6-11e8-8f79-a3da26ed6bae.jpg)

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
