import json
from typing import Dict, Any
import os
import portalocker
from portalocker import LOCK_EX

class BlockHeaderManager:
    """
    Manages the loading and saving of local Block Headers cache.
    """

    def __init__(self, file_path: str):
        """
        Initializes the manager and loads the headers from the specified file.
        :param file_path: The path to the JSON file for storing headers.
        """
        self.file_path = file_path
        self.headers: Dict[str, Any] = self.load()

    def load(self) -> Dict[str, Any]:
        """
        Loads cached block headers from the file.
        Returns a dictionary mapping blockhash to block header data.
        """
        try:
            with open(self.file_path, 'r') as f:
                portalocker.lock(f, LOCK_EX)
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # If the file doesn't exist or is empty, start with an empty dictionary.
            return {}

    def save(self):
        """
        Saves the current headers to the file.
        """
        directory = os.path.dirname(self.file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        with open(self.file_path, 'w') as f:
            portalocker.lock(f,LOCK_EX)
            json.dump(self.headers, f, indent=4)

# Example use
# from block_manager import BlockHeaderManager
# dynamic_header_file_path = f"block_headers_{Config.ACTIVE_NETWORK_NAME}.json"
# manager = BlockHeaderManager(Config.BLOCK_HEADERS_FILE)
#
# print(f"Loaded {len(manager.headers)} block headers.")
#
# manager.headers['some_hash'] = {'data': 'new_header_data'}
#
# manager.save()