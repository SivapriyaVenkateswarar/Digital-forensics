import pytsk3
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")

image_path = r"C:\Users\Sivapriya\Documents\output.raw"

output_dir = r"P:\Digital Forensics\Extracted_Hives"
os.makedirs(output_dir, exist_ok=True)

system_hives = ["SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT"]
system_hive_dir = "/Windows/System32/config"

class DiskImage(pytsk3.Img_Info):
    def __init__(self, image_path):
        super().__init__(image_path)

try:
    img = DiskImage(image_path)
    volume = pytsk3.Volume_Info(img)

    filesystem = None
    for partition in volume:
        if b"NTFS" in partition.desc:
            filesystem = pytsk3.FS_Info(img, offset=partition.start * 512)
            logging.info(f"Found NTFS Partition at Offset: {partition.start * 512}")
            break
    
    if not filesystem:
        logging.error("No NTFS partition found!")
        exit(1)

    for hive in system_hives:
        hive_path = f"{system_hive_dir}/{hive}"  
        try:
            file_obj = filesystem.open(hive_path)
            output_file = os.path.join(output_dir, hive)
            with open(output_file, "wb") as f:
                f.write(file_obj.read_random(0, file_obj.info.meta.size))
            logging.info(f"Extracted: {hive}")
        except Exception as e:
            logging.warning(f"Failed to extract {hive}: {e}")

    logging.info("Registry hive extraction complete!")

except Exception as e:
    logging.error(f"Error accessing filesystem: {e}")
