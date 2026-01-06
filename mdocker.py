#!/usr/bin/env python3
import os
import sys
import ctypes

# Constants for namespaces
CLONE_NEWUTS = 0x04000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNS  = 0x00020000

# Mount flags
MS_REC = 16384
MS_PRIVATE = 1 << 18

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def apply_pid_limit(pid):
    """Apply PID limit using cgroup v2"""
    cgroup_path = f"/sys/fs/cgroup/mdocker_{pid}"
    try:
        os.makedirs(cgroup_path, exist_ok=True)
        try:
            with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
                f.write("+pids")
        except: pass
        with open(f"{cgroup_path}/pids.max", "w") as f:
            f.write("50")
        with open(f"{cgroup_path}/cgroup.procs", "w") as f:
            f.write(str(pid))
    except Exception as e:
        print(f"[Parent] Cgroup Warning: {e}")

def run_inside_container(rootfs_path, args):
    """The final process that becomes PID 1 inside the isolated FS"""
    # 1. Isolate mounts (prevent changes from leaking to host)
    libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)

    # 2. Set hostname
    hostname = b"mdocker"
    libc.sethostname(hostname, len(hostname))

    # 3. Enter the new root filesystem (The "Jail")
    # This makes the provided folder the new '/'
    os.chroot(rootfs_path)
    os.chdir("/")

    # 4. Mount /proc inside the NEW root so tools like 'ps' work
    # We do this AFTER chroot so it populates the container's /proc
    os.makedirs("/proc", exist_ok=True)
    libc.mount(b"proc", b"/proc", b"proc", 0, None)

    print(f"[Child] Container PID 1 started in {rootfs_path}")
    try:
        os.execvp(args[0], args)
    except FileNotFoundError:
        print(f"Error: {args[0]} not found inside the rootfs.")
        sys.exit(1)

def container_setup(rootfs_path, args):
    """Prepare namespaces and fork the actual PID 1"""
    try:
        os.unshare(CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS)
    except PermissionError:
        print("Error: Root privileges required.")
        sys.exit(1)

    pid = os.fork()
    if pid == 0:
        run_inside_container(rootfs_path, args)
    else:
        _, status = os.waitpid(pid, 0)
        sys.exit(os.waitstatus_to_exitcode(status))

def main():
    if len(sys.argv) < 4 or sys.argv[1] != "run":
        print(f"Usage: sudo {sys.argv[0]} run <rootfs_path> <command>")
        print(f"Example: sudo {sys.argv[0]} run ./my_rootfs /bin/sh")
        sys.exit(1)

    rootfs_path = os.path.abspath(sys.argv[2])
    command_args = sys.argv[3:]

    pid = os.fork()
    if pid == 0:
        container_setup(rootfs_path, command_args)
    else:
        apply_pid_limit(pid)
        try:
            os.waitpid(pid, 0)
        except KeyboardInterrupt:
            os.kill(pid, 9)

if __name__ == "__main__":
    main()
