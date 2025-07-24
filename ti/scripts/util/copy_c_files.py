import os
import shutil
import sys

def copy_o_files_flat(src_root, dest_root):
    seen_files = set()
    for dirpath, dirnames, filenames in os.walk(src_root):
        for filename in filenames:
            if filename.endswith('.c') and filename not in seen_files:
                seen_files.add(filename)
                full_src_path = os.path.join(dirpath, filename)
                dest_file = os.path.join(dest_root, filename)
                shutil.copy2(full_src_path, dest_file)
                print(f"Copied: {full_src_path} -> {dest_file}")
            elif filename.endswith('.o'):
                print(f"Skipping duplicate: {filename}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <source_root_directory> <destination_directory>")
        sys.exit(1)

    source_dir = sys.argv[1]
    destination_dir = sys.argv[2]

    if not os.path.isdir(source_dir):
        print(f"Error: Source directory '{source_dir}' not found.")
        sys.exit(1)

    os.makedirs(destination_dir, exist_ok=True)
    copy_o_files_flat(source_dir, destination_dir)
    print("Done copying .c files without preserving folders and skipping duplicates.")

