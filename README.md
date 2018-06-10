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

# usage

~~~
(venv) $ ./collect_vm.py <vm_name>
~~~

Access `Neo4j` web interface at `http://localhost:7474`

## neo4j

~~~
MATCH(n)
RETURN(n)
LIMIT 300;
~~~
