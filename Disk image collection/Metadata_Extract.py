import pytsk3
import os
import datetime
import csv

# Define the output directory
output_dir = r"C:\Users\Sivapriya\Documents\ForensicOutput"
os.makedirs(output_dir, exist_ok=True)  # Create directory if it doesn't exist
output_file = os.path.join(output_dir, "extracted_metadata.csv")

# Define a class for opening raw disk images
class TSK_IMG_INFO(pytsk3.Img_Info):
    def __init__(self, filename):
        self.file = open(filename, "rb")  
        super().__init__(filename)

    def close(self):
        self.file.close()

    def read(self, offset, size):
        self.file.seek(offset)
        return self.file.read(size)

    def get_size(self):
        self.file.seek(0, 2)
        return self.file.tell()

# Function to convert timestamps
def convert_time(tsk_time):
    if tsk_time == 0 or tsk_time is None:
        return "N/A"
    return datetime.datetime.utcfromtimestamp(tsk_time).strftime('%Y-%m-%d %H:%M:%S')

# Function to extract file metadata and save to CSV
def extract_metadata(fs_info, directory, parent_path, csv_writer):
    for entry in directory:
        if not hasattr(entry.info, "name") or not entry.info.name.name:
            continue
        
        entry_name = entry.info.name.name.decode(errors="ignore")
        entry_path = os.path.join(parent_path, entry_name)
        
        if entry.info.meta:
            created_time = convert_time(entry.info.meta.crtime)
            modified_time = convert_time(entry.info.meta.mtime)
            accessed_time = convert_time(entry.info.meta.atime)

            deleted = "Yes" if entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC else "No"

            # Write data to CSV
            csv_writer.writerow([entry_path, created_time, modified_time, accessed_time, deleted])
        
        # Recursively scan directories
        if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            try:
                sub_dir = fs_info.open_dir(path=entry_path)
                extract_metadata(fs_info, sub_dir, entry_path, csv_writer)
            except Exception as e:
                print(f"[!] Error accessing directory {entry_path}: {e}")

# Path to RAW disk image
image_path = r"C:\Users\Sivapriya\Documents\output.raw"

try:
    # Open the RAW disk image
    img_info = TSK_IMG_INFO(image_path)

    # Modify partition_offset if needed (Check with mmls)
    partition_offset = 63 * 512  

    # Open file system
    fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
    root_dir = fs_info.open_dir(path="/")

    print("[*] Extracting File System Metadata...")

    # Open CSV file for writing
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["File Path", "Created", "Modified", "Accessed", "Deleted"])

        # Start extracting metadata
        extract_metadata(fs_info, root_dir, "/", csv_writer)

    print(f"[✔] Metadata Extraction Complete! Output saved in: {output_file}")

except Exception as e:
    print(f"[✘] Error: {e}")
