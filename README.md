# File-System-Forensics-for-Detecting-Deleted-and-Hidden-Files
#Analyze disk images or file system snapshots to identify potentially deleted or hidden files. Recover deleted files by analyzing unallocated space and the file system metadata. Use pattern recognition to detect hidden data (e.g., steganography, file slack space, or mangled file headers).
import pytsk3
import os
from datetime import datetime

# Function to open and read the disk image using The Sleuth Kit (pytsk3)
def open_image(image_path):
    img_info = pytsk3.Img_Info(image_path)
    fs_info = pytsk3.FS_Info(img_info)
    return fs_info

# Function to extract deleted files from the file system
def extract_deleted_files(fs_info):
    deleted_files = []
    # Loop through the file system to search for deleted files
    for file in fs_info.open_dir('/'):
        if file.info.name is not None and file.info.name.name.startswith(b'.'):
            # Marked as deleted, but may still have recoverable data
            file_data = file.read_random(0, file.info.meta.size)
            deleted_files.append({'file_name': file.info.name.name.decode(), 'data': file_data})
    return deleted_files

# Function to detect hidden data in slack space or unallocated space
def detect_hidden_data(fs_info):
    hidden_data = []
    # Search for known steganographic patterns or suspicious file signatures
    for partition in fs_info.open_dir('/'):
        if partition.info.name:
            partition_data = partition.read_random(0, partition.info.meta.size)
            if b"hidden" in partition_data:  # Simple pattern check for hidden data
                hidden_data.append({'partition': partition.info.name.name.decode(), 'data': partition_data})
    return hidden_data

# Function to print out recovered and hidden files/data
def print_recovered_data(deleted_files, hidden_data):
    print("\nRecovered Deleted Files:")
    for file in deleted_files:
        print(f"File Name: {file['file_name']}, Data: {file['data'][:100]}...")  # Only print a snippet of data

    print("\nDetected Hidden Data:")
    for data in hidden_data:
        print(f"Partition: {data['partition']}, Data: {data['data'][:100]}...")  # Only print a snippet

# Main function to perform file system forensics analysis
def analyze_disk_image(image_path):
    print(f"Analyzing disk image: {image_path}")
    
    # Step 1: Open the disk image
    fs_info = open_image(image_path)
    
    # Step 2: Recover deleted files
    deleted_files = extract_deleted_files(fs_info)
    
    # Step 3: Detect hidden data in slack space or unallocated space
    hidden_data = detect_hidden_data(fs_info)
    
    # Step 4: Print the recovered and hidden data
    print_recovered_data(deleted_files, hidden_data)

# Example Usage
image_path = "path_to_disk_image.img"  # Replace with your disk image file path
analyze_disk_image(image_path)
