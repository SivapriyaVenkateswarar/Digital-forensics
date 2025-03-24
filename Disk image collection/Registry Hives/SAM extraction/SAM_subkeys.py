from regipy.registry import RegistryHive

sam_hive = RegistryHive(r"D:\Digital forensics\Extracted_Files\Disk_Img_1\Registry_Hives (under process)\Windows\System32\Config\SAM")

def list_subkeys_recursively(key, depth=0):
    indent = "    " * depth
    print(f"{indent}- {key.name}")
    
    for subkey in key.iter_subkeys():
        list_subkeys_recursively(subkey, depth + 1)

print("[*] Recursively listing all subkeys in SAM hive:")
list_subkeys_recursively(sam_hive.root)


from regipy.registry import RegistryHive

sam_hive = RegistryHive(r"D:\Digital forensics\Extracted_Files\Disk_Img_1\Registry_Hives (under process)\Windows\System32\Config\SAM")

try:
    users_key = sam_hive.get_key("SAM\\SAM\\Domains\\Account\\Users")
    print("\n[*] Subkeys inside 'Users':")
    
    for subkey in users_key.iter_subkeys():
        print(f" - {subkey.name}")

    # Try fetching the "Names" subkey
    names_key = users_key.get_subkey("Names")
    print("\n[*] Extracted User Accounts:\n")

    for subkey in names_key.iter_subkeys():
        print(f" - {subkey.name}")

except Exception as e:
    print(f"Error: {e}")

