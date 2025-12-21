import os
import subprocess
from .namespaces import (
    apply_basic_namespaces,
    set_container_hostname
)

def run_container(command: str):
    print("[*] Starting container runtime")

    # Apply namespaces
    apply_basic_namespaces()

    pid = os.fork()

    if pid == 0:
        # Child process
        print("[*] Child process started")
        set_container_hostname()

        # Mount /proc for PID namespace visibility
        os.makedirs("/proc", exist_ok=True)
        subprocess.run(
            ["mount", "-t", "proc", "proc", "/proc"],
            check=True
        )

        print(f"[*] Executing command: {command}")
        subprocess.run(command.split(), check=True)

        os._exit(0)

    else:
        # Parent process
        os.waitpid(pid, 0)
        print("[*] Container process exited")
