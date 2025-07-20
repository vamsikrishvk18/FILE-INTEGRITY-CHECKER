import hashlib
import os
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='file_integrity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FileIntegrityChecker:
    def __init__(self, baseline_file='baseline.json'):
        self.baseline_file = baseline_file
        self.baseline_hashes = self.load_baseline()

    def calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return None

    def load_baseline(self):
        """Load the baseline hash database from a JSON file."""
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading baseline: {e}")
                return {}
        return {}

    def save_baseline(self):
        """Save the baseline hash database to a JSON file."""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baseline_hashes, f, indent=4)
            logging.info("Baseline saved successfully.")
        except Exception as e:
            logging.error(f"Error saving baseline: {e}")

    def create_baseline(self, paths):
        """Create a baseline of hashes for the specified files or directories."""
        self.baseline_hashes = {}
        for path in paths:
            if os.path.isfile(path):
                hash_value = self.calculate_hash(path)
                if hash_value:
                    self.baseline_hashes[path] = hash_value
                    logging.info(f"Baseline hash for {path}: {hash_value}")
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        hash_value = self.calculate_hash(file_path)
                        if hash_value:
                            self.baseline_hashes[file_path] = hash_value
                            logging.info(f"Baseline hash for {file_path}: {hash_value}")
        self.save_baseline()

    def check_integrity(self, paths):
        """Check the integrity of files against the baseline."""
        changes_detected = False
        for path in paths:
            if os.path.isfile(path):
                self._check_file(path)
                changes_detected = True if self._check_file(path) else changes_detected
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        changes_detected = True if self._check_file(file_path) else changes_detected
            else:
                logging.warning(f"Path does not exist: {path}")
        return changes_detected

    def _check_file(self, file_path):
        """Helper method to check integrity of a single file."""
        current_hash = self.calculate_hash(file_path)
        if not current_hash:
            return False

        if file_path not in self.baseline_hashes:
            logging.warning(f"File not in baseline: {file_path}")
            return True
        elif self.baseline_hashes[file_path] != current_hash:
            logging.error(f"Integrity violation for {file_path}. Expected: {self.baseline_hashes[file_path]}, Got: {current_hash}")
            return True
        else:
            logging.info(f"File {file_path} is unchanged.")
            return False

def main():
    # Example paths to monitor (modify as needed)
    paths_to_monitor = [
        '/etc/passwd',  # Example critical system file
        '/var/www/html'  # Example directory
    ]

    checker = FileIntegrityChecker()

    # Menu for user interaction
    while True:
        print("\nFile Integrity Checker")
        print("1. Create baseline")
        print("2. Check file integrity")
        print("3. Exit")
        choice = input("Enter choice (1-3): ")

        if choice == '1':
            checker.create_baseline(paths_to_monitor)
            print("Baseline created successfully. Check file_integrity.log for details.")
        elif choice == '2':
            if not checker.baseline_hashes:
                print("No baseline found. Please create a baseline first.")
            else:
                changes_detected = checker.check_integrity(paths_to_monitor)
                if changes_detected:
                    print("Changes detected! Check file_integrity.log for details.")
                else:
                    print("No changes detected.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
