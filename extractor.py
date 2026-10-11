import os
import tarfile

tar_path = "ember_dataset_2018_2.tar.bz2"
extract_path = "data/ember2018"

with tarfile.open(tar_path, "r:bz2") as tar:
    if hasattr(tarfile, "data_filter"):
        # Python 3.12+ / recent 3.8-3.11: blocks path traversal, links and devices
        tar.extractall(path=extract_path, filter="data")
    else:
        base = os.path.realpath(extract_path)
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(base, member.name))
            if member.issym() or member.islnk() or not target.startswith(base + os.sep):
                raise ValueError(f"Unsafe path in archive: {member.name}")
        tar.extractall(path=extract_path)

print("  Extracted to:", extract_path)