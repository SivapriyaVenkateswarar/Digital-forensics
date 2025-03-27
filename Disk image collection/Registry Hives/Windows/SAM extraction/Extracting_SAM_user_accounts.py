from regipy.registry import RegistryHive
import csv

def extract_user_keys(sam_hive_path):
    try:
        sam_hive = RegistryHive(sam_hive_path)
        users_key = sam_hive.get_key("SAM\\SAM\\Domains\\Account\\Users")
        return [user_subkey.name for user_subkey in users_key.iter_subkeys()]
    except Exception as e:
        print(f"Error extracting user keys: {e}")
        return []

def extract_usernames(sam_hive_path):
    try:
        sam_hive = RegistryHive(sam_hive_path)
        users_key = sam_hive.get_key("SAM\\SAM\\Domains\\Account\\Users")
        names_key = users_key.get_subkey("Names")
        return [user_subkey.name for user_subkey in names_key.iter_subkeys()]
    except Exception as e:
        print(f"Error extracting usernames: {e}")
        return []

sam_hive_path = r"P:\Digital forensics\Disk_imaging\Disk_Image_1\Registry_Hives\Windows\System32\Config\SAM"
output_file = r"P:\Digital forensics\user_accounts.csv"

user_keys = extract_user_keys(sam_hive_path)
usernames = extract_usernames(sam_hive_path)

max_length = max(len(user_keys), len(usernames))
user_keys += ["Unknown"] * (max_length - len(user_keys))
usernames += ["Unknown"] * (max_length - len(usernames))

if user_keys or usernames:
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["User Key (RID)", "Username"])  
        writer.writerows(zip(user_keys, usernames))  

    print(f"Extracted user keys and usernames saved to {output_file}")
else:
    print("No user data found.")
