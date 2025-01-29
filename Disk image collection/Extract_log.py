import pytsk3
import os

# Define a custom class for opening raw disk images
class TSK_IMG_INFO(pytsk3.Img_Info):
    def __init__(self, filename):
        self.file = open(filename, "rb")  # Open in binary mode
        super().__init__(filename)

    def close(self):
        self.file.close()

    def read(self, offset, size):
        self.file.seek(offset)
        return self.file.read(size)

    def get_size(self):
        self.file.seek(0, 2)
        return self.file.tell()

# Function to extract a file
def extract_file(fs_info, file_entry, output_dir, parent_path):
    try:
        file_name = file_entry.info.name.name.decode(errors="ignore")
        file_path = os.path.join(parent_path, file_name)  # Relative path
        output_path = os.path.join(output_dir, file_path.lstrip("/"))  # Full path

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Open the file in the disk image
        file_obj = file_entry.read_random(0, file_entry.info.meta.size)

        # Write to local storage
        with open(output_path, "wb") as out_file:
            out_file.write(file_obj)

        print(f"[✔] Extracted: {output_path}")

    except Exception as e:
        print(f"[✘] Failed to extract {file_entry.info.name.name.decode(errors='ignore')}: {e}")

# Function to recursively search for .log files
def find_log_files(fs_info, directory, parent_path, output_dir):
    for entry in directory:
        if not hasattr(entry.info, "name") or not entry.info.name.name:
            continue
        
        entry_name = entry.info.name.name.decode(errors="ignore")
        entry_path = os.path.join(parent_path, entry_name)

        # Check if it's a directory
        if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            try:
                sub_dir = fs_info.open_dir(path=entry_path)
                find_log_files(fs_info, sub_dir, entry_path, output_dir)
            except Exception as e:
                print(f"[!] Error accessing directory {entry_path}: {e}")

        # Check if it's a log file
        elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
            if entry_name.lower().endswith(".log"):  # Match .log files
                extract_file(fs_info, entry, output_dir, parent_path)

# Path to RAW disk image
image_path = r"C:\Users\Sivapriya\Documents\output.raw"
output_dir = r"D:\Digital forensics\Logs"  # Change to your preferred output directory

try:
    # Open the RAW disk image
    img_info = TSK_IMG_INFO(image_path)

    # Partition offset (Modify if needed)
    partition_offset = 63 * 512  # Default start sector * bytes per sector

    # Open NTFS filesystem
    fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
    root_dir = fs_info.open_dir(path="/")

    print("[*] Filesystem opened! Searching for log files...")
    
    find_log_files(fs_info, root_dir, "/", output_dir)

    print("[✔] Log file extraction complete!")

except Exception as e:
    print(f"[✘] Error accessing filesystem: {e}")
