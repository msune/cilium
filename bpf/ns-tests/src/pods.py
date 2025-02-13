from src.common import *

def pod_create(node_id:int, pod_id:int):
    """
    Creates a mockup pod in a worker node

    node_id: an integer identifying the node
    pod_id: an integer identifiying the pod within the node

    nodeX_pY is the emulated's pod netns
    """
    try:
        # Create base NS
        node_ns = "node"+str(node_id)
        ns = "node"+str(node_id)+"_p"+str(pod_id)
        shell_exec(f"ip netns add {ns}")

        # Loopback
        shell_exec(f"ip link set up dev lo", ns)

        # Create pod's main veth iface
        # XXX add support for multi-network
        shell_exec(f"ip link add lxc00{pod_id} type veth peer name eth0_", node_ns)
        shell_exec(f"ip link set up dev lxc00{pod_id}", node_ns)
        shell_exec(f"ip link set dev eth0_ netns {ns}", node_ns)
        shell_exec(f"ip link set eth0_ name eth0", ns)
        shell_exec(f"ip link set up dev eth0", ns)

    except Exception as e:
        print(f"Unable to create node '{node_id}': {e}")
        raise e

def pod_destroy(node_id:int, pod_id:int):
    try:
        ns = "node"+str(node_id)+"_p"+str(pod_id)

        # Delete iface pair
        shell_exec(f"ip link del eth0", ns)

        # Delete NS
        ns = "node"+str(node_id)+"_p"+str(pod_id)
        shell_exec(f"ip netns delete {ns}")
    except Exception as e:
        print(f"Unable to destroy node '{node_id}': {e}")
        raise e
