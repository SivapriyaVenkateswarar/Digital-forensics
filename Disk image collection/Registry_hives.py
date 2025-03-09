import pytsk3
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")

class TSK_IMG_INFO(pytsk3.Img_Info):
    def __init__(self, filename):
        self.file = open(filename, "rb")  
        super().__init__()

    def close(self):
        self.file.close()

    def read(self, offset, size):
        self.file.seek(offset)
        return self.file.read(size)

    def get_size(self):
        self.file.seek(0, 2)
        return self.file.tell()

    def __del__(self):
        self.close()

def extract_file(fs_info, file_entry, output_dir, relative_path):
    """Extracts a file from the forensic image to the output directory."""
    try:
        file_name = file_entry.info.name.name.decode(errors="ignore")
        full_path = os.path.join(output_dir, relative_path.lstrip("/")).replace("/", "\\")
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        if not file_entry.info.meta or file_entry.info.meta.size is None:
            logging.warning(f"[!] Skipping {file_name}: No metadata or size info.")
            return

        file_size = file_entry.info.meta.size
        with open(full_path, "wb") as out_file:
            offset = 0
            while offset < file_size:
                chunk = file_entry.read_random(offset, min(4096, file_size - offset))
                if not chunk:
                    break
                out_file.write(chunk)
                offset += len(chunk)

        logging.info(f"[✔] Extracted: {full_path}")

    except Exception as e:
        logging.error(f"[✘] Failed to extract {file_name}: {e}")

def find_registry_hives(fs_info, directory, relative_path, output_dir, hive_names):
    """Finds and extracts registry hives in the given directory."""
    for entry in directory:
        if not hasattr(entry.info, "name") or not entry.info.name.name:
            continue

        entry_name = entry.info.name.name.decode(errors="ignore")
        entry_full_path = os.path.join(relative_path, entry_name)  

        if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
            if entry_name in hive_names:
                extract_file(fs_info, entry, output_dir, entry_full_path)

def list_directory(fs_info, path):
    """Lists accessible directories inside a given path."""
    try:
        directory = fs_info.open_dir(path)
        accessible_dirs = []
        logging.info(f"\n[*] Listing directories inside: {path}")

        for entry in directory:
            if hasattr(entry.info, "name") and entry.info.name.name:
                entry_name = entry.info.name.name.decode(errors="ignore")
                
                if entry_name in [".", ".."]:
                    continue  

                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    full_path = f"{path}/{entry_name}"  # Use forward slashes
                    try:
                        fs_info.open_dir(full_path)  # Test accessibility
                        accessible_dirs.append(full_path)
                        logging.info(f"  [✔] Accessible: {entry_name}")
                    except:
                        logging.warning(f"  [!] Inaccessible: {entry_name}")

        return accessible_dirs  

    except Exception as e:
        logging.warning(f"[!] Could not list contents of {path}: {e}")
        return []

image_path = r"C:\Users\Sivapriya\Documents\output.raw"
output_dir = r"D:\Digital forensics\Registry_Hives"

try:
    img_info = TSK_IMG_INFO(image_path)

    partition_offset = 63 * 512  
    fs_info = pytsk3.FS_Info(img_info, offset=partition_offset)
    logging.info("[*] Filesystem opened! Searching for registry hives...")

    # System-wide registry hives (from Windows/System32/Config)
    system_hive_dir = "/Windows/System32/Config"
    system_hives = ["SAM", "SECURITY", "SYSTEM", "SOFTWARE", "DEFAULT"]

    try:
        dir_entry = fs_info.open_dir(system_hive_dir)
        find_registry_hives(fs_info, dir_entry, system_hive_dir, output_dir, system_hives)
    except Exception as e:
        logging.warning(f"[!] Could not access {system_hive_dir}: {e}")

    # User-specific registry hives (from /Documents and Settings/<user>/NTUSER.DAT)
    user_directory = "/Documents and Settings"
    try:
        user_dirs = list_directory(fs_info, user_directory)
        for user_dir in user_dirs:
            try:
                user_hive_path = f"{user_dir}/NTUSER.DAT"
                file_entry = fs_info.open(user_hive_path)
                extract_file(fs_info, file_entry, output_dir, user_hive_path)
            except Exception as e:
                logging.warning(f"[!] Could not extract NTUSER.DAT from {user_dir}: {e}")

    except Exception as e:
        logging.warning(f"[!] Could not access {user_directory}: {e}")

    logging.info("[✔] Registry hive extraction complete!")

except Exception as e:
    logging.error(f"[✘] Error accessing filesystem: {e}")
