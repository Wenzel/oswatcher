# OSWatcher

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

Follow the instructions in the `db` directory to run a it inside a docker container.

# Usage

~~~
(venv) $ python -m oswatcher.capture <vm_name> hooks.json
~~~

Example:
![Capturing ubuntu filesystem](https://user-images.githubusercontent.com/964610/47535862-14ddbb00-d8c6-11e8-88cd-efa5db339bb8.jpg)

Access `Neo4j` web interface at `http://localhost:7474`
![ubuntu etc neo4j](https://user-images.githubusercontent.com/964610/47535864-18714200-d8c6-11e8-885b-27d17c8d6235.png)

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
