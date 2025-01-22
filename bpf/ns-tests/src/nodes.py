import subprocess

def _exec(cmd):
    try:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            raise Exception(f"Unknown error while running '{cmd}'. Result: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Unable to execute '{cmd}': {e}")
        raise e

def node_create(node_id: int):
    """
    Creates a mockup of a worker node

    node_id: an integer identifying the node

    nodeX is the emulated host's default namespace
    """
    try:
        ns = "node"+str(node_id)
        _exec(['ip', 'netns', 'add', ns])
        _exec(['ip', 'netns', 'exec', ns, "ip", "link", "set", "up", "dev", "lo"])
    except subprocess.CalledProcessError as e:
        print(f"Unable to create node '{node_id}': {e}")
        raise e

def node_destroy(node_id: int):
    try:
        _exec(['ip', 'netns', 'delete', "node"+str(node_id)])
    except subprocess.CalledProcessError as e:
        print(f"Unable to destroy node '{node_id}': {e}")
        raise e
