import tarfile

tar_path = "ember_dataset_2018_2.tar.bz2"
extract_path = "data/ember2018"

with tarfile.open(tar_path, "r:bz2") as tar:
    tar.extractall(path=extract_path)

print("  Extracted to:", extract_path)