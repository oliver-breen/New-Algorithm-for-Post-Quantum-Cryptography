import os
import shutil

src = 'quantaweave/pq_schemes_clean.py'
dst = 'quantaweave/pq_schemes.py'

if os.path.exists(src):
    if os.path.exists(dst):
        os.remove(dst)
    os.rename(src, dst)
    print(f"Moved {src} to {dst}")
else:
    print(f"{src} does not exist")
