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
        file_name = f"{args.process_name}.pause.flag"
        try:
            with open(file_name, 'w') as f:
                pass
            print(f"'{file_name}' created. Process '{args.process_name}' will pause.")
        except IOError as e:
            print(f"Error creating file '{file_name}': {e}")

    elif args.action == 'resume':
        file_name = f"{args.process_name}.pause.flag"
        try:
            if os.path.exists(file_name):
                os.remove(file_name)
                print(f"'{file_name}' removed. Process '{args.process_name}' will resume.")
            else:
                print(f"Process '{args.process_name}' is not currently paused (no pause flag found).")
        except IOError as e:
            print(f"Error removing file '{file_name}': {e}")
            
    elif args.action == 'stop':
        file_name = f"{args.process_name}.stop.flag"
        try:
            with open(file_name, 'w') as f:
                pass
            print(f"'{file_name}' created. Process '{args.process_name}' will stop gracefully.")
        except IOError as e:
            print(f"Error creating file '{file_name}': {e}")

if __name__ == "__main__":
    main()