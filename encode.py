import base64
import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
from PIL import Image

def select_file(title):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    return filedialog.askopenfilenames(initialdir=os.path.expanduser("~/Documents"),title=title)
    
def encode(src,data,dst):
    img=Image.open(src, 'r')
    width,height=img.size
    array=np.array(list(img.getdata()))

    if img.mode=='RGB':
        n=3
    elif img.mode=='RGBA':
        n=4
    total_pixels=array.size//n

def main():
    target_file = select_file("target file")
    sensitive_info = select_file("sensitive information")
    # for file_path in files:
    #     with open(file_path, "rb") as f:
    #         file_data = f.read()
    #         encoded_data = base64.b64encode(file_data).decode("utf-8")
    #         print(f"Encoded {file_path}: {encoded_data}")

    return

if __name__== "__main__":
    main() 