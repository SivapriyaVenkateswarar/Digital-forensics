from regipy.registry import RegistryHive
import csv
import struct
import datetime

def convert_windows_filetime(filetime):

    if filetime == 0:
        return "Never Logged In"

    try:
        timestamp = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "Invalid Timestamp"

def extract_last_logins(sam_hive_path):

    try:
        sam_hive = RegistryHive(sam_hive_path)
        users_key = sam_hive.get_key("SAM\\SAM\\Domains\\Account\\Users")
        last_logins = []

        for user_subkey in users_key.iter_subkeys():
            rid = user_subkey.name  
            try:
                f_value = user_subkey.get_value("F") 

                if f_value is None:
                    last_login = "No 'F' Value"
                elif len(f_value) >= 16:
                    last_login_raw = struct.unpack("<Q", f_value[8:16])[0]  
                    last_login = convert_windows_filetime(last_login_raw)
                else:
                    last_login = "Insufficient Data"

            except Exception as e:
                last_login = f"Error: {e}"

            last_logins.append((rid, last_login))

        return last_logins

    except Exception as e:
        print(f"Error extracting last login timestamps: {e}")
        return []

sam_hive_path = r"P:\Digital forensics\Disk_imaging\Disk_Image_1\Registry_Hives\Windows\System32\Config\SAM"
output_file = r"P:\Digital forensics\last_logins.csv"

last_logins = extract_last_logins(sam_hive_path)

if last_logins:
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["User Key (RID)", "Last Login Timestamp"]) 
        writer.writerows(last_logins)  
    print(f"[✔] Extracted last login timestamps saved to {output_file}")
else:
    print("[✘] No last login data found.")
