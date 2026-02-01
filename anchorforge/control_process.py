# -----------------------------------------------------------------------------
# Project: AnchorForge v0.2
# File:    control_process.py
# (c)      2025-2026 Wolfgang Lohmann
# License: MIT
# -----------------------------------------------------------------------------

# control_process.py
"""
This script provides a generic way to control long-running processes
by creating or deleting flag files.

Examples:
- Pause the coingecko batch: python control_process.py coingecko pause
- Resume the coingecko batch: python control_process.py coingecko resume
- Stop the monitor:          python control_process.py monitor stop
"""
import os
import argparse
import sys

try:
    from anchorforge.config import Config
except ImportError:
    # Fallback logic if package structure is different or running standalone
    try:
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from anchorforge.config import Config
    except ImportError:
        Config = None

def get_flag_path(process_name, flag_type):
    """
    Constructs the path for the flag file, ensuring it goes into the 'runtime' directory.
    """
    filename = f"{process_name}.{flag_type}.flag"
    
    # Use a dedicated runtime directory instead of the root folder.
    # If Config defines a RUNTIME_DIR, use it. Otherwise default to 'runtime'.
    runtime_dir = "runtime"
    if Config and hasattr(Config, 'RUNTIME_DIR'):
        runtime_dir = Config.RUNTIME_DIR
    
    # Ensure directory exists
    if not os.path.exists(runtime_dir):
        try:
            os.makedirs(runtime_dir, exist_ok=True)
        except OSError as e:
            print(f"Error creating runtime directory '{runtime_dir}': {e}")
            return filename # Fallback to current dir if we can't create runtime

    return os.path.join(runtime_dir, filename)


def main():
    parser = argparse.ArgumentParser(
        description="Control long-running processes via flag files."
    )
    
    parser.add_argument(
        "process_name", 
        type=str, 
        help="The name of the process to control (e.g., 'coingecko', 'monitor')."
    )
    
    parser.add_argument(
        "action", 
        choices=['pause', 'resume', 'stop'], 
        help="The action to perform."
    )

    args = parser.parse_args()

    if args.action == 'pause':
        file_name = get_flag_path(args.process_name, "pause")
        try:
            with open(file_name, 'w') as f:
                pass
            print(f"'{file_name}' created. Process '{args.process_name}' will pause.")
        except IOError as e:
            print(f"Error creating file '{file_name}': {e}")

    elif args.action == 'resume':
        file_name = get_flag_path(args.process_name, "pause")
        try:
            if os.path.exists(file_name):
                os.remove(file_name)
                print(f"'{file_name}' removed. Process '{args.process_name}' will resume.")
            else:
                print(f"Process '{args.process_name}' is not currently paused (no pause flag found).")
        except IOError as e:
            print(f"Error removing file '{file_name}': {e}")
            
    elif args.action == 'stop':
        file_name = get_flag_path(args.process_name, "stop")
        try:
            with open(file_name, 'w') as f:
                pass
            print(f"'{file_name}' created. Process '{args.process_name}' will stop gracefully.")
        except IOError as e:
            print(f"Error creating file '{file_name}': {e}")

if __name__ == "__main__":
    main()