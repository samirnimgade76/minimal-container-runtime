import os
import subprocess

# Namespace flags
CLONE_NEWUTS = 0x04000000
CLONE_NEWPID = 0x20000000

def apply_basic_namespaces():
    """
    Apply basic UTS and PID namespaces.
    """
    os.unshare(CLONE_NEWUTS | CLONE_NEWPID)

def set_container_hostname(hostname: str = "mycontainer"):
    """
    Set hostname inside the container.
    """
    subprocess.run(
        ["hostname", hostname],
        check=True
    )
