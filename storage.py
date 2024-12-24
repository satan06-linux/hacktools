from asyncio import log  # pip install asyncio
import os  # pip install os

class StorageCalculator:
    def __init__(self, directory):
        self.directory = directory

    def calculate_total_size(self):
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(self.directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.isfile(filepath):  # Ensure it's a file
                    total_size += os.path.getsize(filepath)
        return total_size

    def convert_size(self, size_in_bytes):
        """Convert size in bytes to a human-readable format."""
        if size_in_bytes == 0:
            return "0 Bytes"
        size_name = ("Bytes", "KB", "MB", "GB", "TB")
        i = int(log(size_in_bytes, 1024))
        p = pow(1024, i)
        s = round(size_in_bytes / p, 2)
        return f"{s} {size_name[i]}"

    def display_storage_info(self):
        """Display the total storage size in a human-readable format."""
        total_size = self.calculate_total_size()
        readable_size = self.convert_size(total_size)
        print(f"Total storage size in '{self.directory}': {readable_size}")

if __name__ == "__main__":
    directory = input("Enter the directory path to calculate storage size: ")
    if os.path.exists(directory) and os.path.isdir(directory):
        calculator = StorageCalculator(directory)
        calculator.display_storage_info()
    else:
        print("Invalid directory. Please enter a valid path.")
