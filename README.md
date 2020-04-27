# OSWatcher

![](https://github.com/Wenzel/oswatcher/workflows/Capture%20Filesystem%20in%20git/badge.svg)
[![Join the chat at https://gitter.im/oswatcher/Lobby](https://badges.gitter.im/trailofbits/algo.svg)](https://gitter.im/oswatcher/Lobby)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)
[![tokei](https://tokei.rs/b1/github/Wenzel/oswatcher)](https://github.com/Wenzel/oswatcher)
[![repo size](https://img.shields.io/github/repo-size/Wenzel/oswatcher)](https://github.com/Wenzel/oswatcher)

> Tracking the evolution of operating systems over time

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

- `python >= 3.7`
- `virtualenv`
- [`libguestfs`](http://libguestfs.org/)
- [`Docker`](https://www.docker.com/) (_optional_)

## Install

1. Clone repo and submodules
~~~
git clone https://github.com/Wenzel/oswatcher.git
cd oswatcher
git submodule update --init
~~~

2. Install system dependencies

On `Ubuntu 18.04`

~~~
sudo apt-get install virtualenv python3-virtualenv libguestfs0 libguestfs-dev python3-guestfs python3-dev pkg-config libvirt-dev
~~~

3. Create a `Python3` virtualenv
~~~
virtualenv --system-site-packages -p python3 venv
source venv/bin/activate
pip install .
~~~

Note: We have to use `--system-site-packages` because `libguestfs` is not
available on `pip`.

## VM setup

OSWatcher works on VMs stored in `libvirt`, either via `qemu:///session`
or `qemu:///system`.

Note: `qemu:///session` is recommended as it requires less permission
and should work without further configuration.

## Example Usage: Filesystem capture in Git

### Hooks configuration

Open `hooks.json` and edit `/path/to/repo` to an empty git repository (outside of `oswatcher`'s git repo).

~~~JSON
        {
            "name": "hooks.filesystem.GitFilesystemHook",
            "configuration":
            {
                "repo": "/home/user/test/git_fs"
            }
        }
~~~

Start the capture tool on a `VM` and specify the hooks configuration to start
capturing the VM's filesystem in the previously configured `git` repository.

~~~
(venv) $ oswatcher [options] <vm_name> hooks.json
~~~

## Demo

Capturing Windows XP Filesystem in a git repository ([high-quality](https://drive.google.com/open?id=15JF_Pr-kpCLkeHwaX_cfHUq744BZwsNo))

![Capturing winxp
filesystem](https://user-images.githubusercontent.com/964610/78451333-923d5b80-7674-11ea-854d-37a53bd7d3ae.gif)

## Advanced Usage

### Neo4j

Some of `OSWatcher`'s plugins are using `neo4j` as a database.
- `system.OperatingSystemHook`
- `filesystem.Neo4jFilesystemHook`
- `security.SecurityHook`

Follow the instructions in the `db` directory to run a `Neo4j` inside a docker
container.

Modify your `hooks.json` to include a `neo4j` dictionary in the general `configuration` section.

You will also need to include the:
- `OperatingSystemHook` at least.

The rest is optional. 

To visualize the filesystem in `Neo4j`, include the `FilesystemHook` and the `Neo4jFilesystemHook`, like the example below:
~~~JSON
{
    "configuration":
    {
        "neo4j_db": {
            "enabled": true,
            "delete": false,
            "replace": false
        },
        "desktop_ready_delay": 90
    },
    "hooks":
    [
        {
            "name": "hooks.filesystem.LibguestfsHook"
        },
        {
            "name": "hooks.filesystem.FilesystemHook",
            "configuration":
            {
                "enumerate": true,
                "log_progress": true,
                "log_progress_delay": 10
            }
        },
        {
            "name": "hooks.filesystem.Neo4jFilesystemHook"
        }
    ]
}

~~~

Access `Neo4j` web interface at `http://localhost:7474` ![ubuntu etc
neo4j](https://user-images.githubusercontent.com/964610/47535864-18714200-d8c6-11e8-885b-27d17c8d6235.png)

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
