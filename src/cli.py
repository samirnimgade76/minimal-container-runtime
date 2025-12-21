import argparse
from .runtime import run_container

def main():
    parser = argparse.ArgumentParser(
        description="Minimal Container Runtime"
    )
    parser.add_argument(
        "command",
        help="Command to run inside the container"
    )

    args = parser.parse_args()
    run_container(args.command)

if __name__ == "__main__":
    main()
