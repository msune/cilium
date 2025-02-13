from src.common import *

def node_create(node_id: int):
    """
    Creates a mockup of a worker node

    node_id: an integer identifying the node

    nodeX is the emulated host's default namespace
    """
    try:
        ns = "node"+str(node_id)
        shell_exec(f"ip netns add {ns}")

        # Loopback
        shell_exec(f"ip link set up dev lo", ns)

        # Create node's eth0
        shell_exec(f"ip link add eth0 type veth peer name n{node_id}_eth0", ns)
        shell_exec(f"ip link set up dev eth0", ns)

        # Bring the other pair in the default NS
        shell_exec(f"ip link set dev n{node_id}_eth0 netns 1", ns)
        shell_exec(f"ip link set up dev n{node_id}_eth0")
    except Exception as e:
        print(f"Unable to create node '{node_id}': {e}")
        raise e

def node_destroy(node_id: int):
    try:
        ns = "node"+str(node_id)

        # Destroy eth0 in the node's ns
        shell_exec(f"ip link del dev eth0", ns)

        # Destroy NS
        shell_exec(f"ip netns delete {ns}")
    except Exception as e:
        print(f"Unable to destroy node '{node_id}': {e}")
        raise e
