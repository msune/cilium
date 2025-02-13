import subprocess
import shlex

def shell_exec(cmd, ns=""):
    cmd_ = []
    if ns != "":
        cmd_.extend(["ip", "netns", "exec", ns])
    cmd_.extend(shlex.split(cmd))

    try:
        result = subprocess.run(cmd_)
        if result.returncode != 0:
            raise Exception(f"Unknown error while running '{cmd_}'. Result: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Unable to execute '{cmd_}': {e}")
        raise e
