# OSWatcher

# requirements

- `libguestfs`
- `python3`
- `virtualenv`

# setup

~~~
virtualenv --system-site-packages -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
~~~

Note: We have to use `--system-site-packages` because `libguestfs` is not
available on `pip`.

# usage

~~~
(venv) $ python -m oswatcher.capture <vm_name> hooks.json
~~~

Access `Neo4j` web interface at `http://localhost:7474`

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
