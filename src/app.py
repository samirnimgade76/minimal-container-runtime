import os
import sys

def main():
    app_env = os.getenv("APP_ENV", "dev")
    app_version = os.getenv("APP_VERSION", "0.0")

    print("Hello – running inside the minimal container runtime")
    print(f"Environment: {app_env}")
    print(f"Version: {app_version}")

    if len(sys.argv) > 1:
        print("Arguments passed to app:", sys.argv[1:])

if __name__ == "__main__":
    main()
