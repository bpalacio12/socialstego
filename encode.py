import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
from PIL import Image

def select_file(title):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    return filedialog.askopenfilename(initialdir=os.path.expanduser("~/Documents"),title=title)

def file_to_bytes(file_path):
    with open(file_path, "rb") as f:
        for byte in f.read():
            for i in range(7,-1,-1):
                yield(byte>>i)&1

def marker_bits():
    marker = b"$bpg0"
    for byte in marker:
        for i in range(7,-1,-1):
            yield(byte>>i)&1

def encode(src,data,dst):
    img=Image.open(src, 'r')
    width,height=img.size
    array=np.array(list(img.getdata()))

    if img.mode=='RGB':
        n=3
    elif img.mode=='RGBA':
        n=4
    else:
        raise ValueError("Unsuported Image mode")
    
    total_pixels=array.size//n

    bit_gen= (bit for bit in list(data)+list(marker_bits()))

    for p in range(total_pixels):
        for q in range(0,3):
            try:
                array[p][q]=(array[p][q] & ~1) | next(bit_gen)
            except StopIteration:
                break

    array=array.reshape(height,width,n)
    enc_img = Image.fromarray(array.astype('uint8'), img.mode)
    enc_img.save(dst)
    print("Image successfully encoded")

def decode(src,dst):
    img=Image.open(src,'r')
    array=np.array(list(img.getdata()))
    bits=[]

    for pixel in array:
        for channel in pixel[:3]:
            bits.append(channel & 1)

    data_bytes = bytearray()
    for i in range(0,len(bits),8):
        byte=0
        for j in range(8):
            if i+j < len(bits):
                byte=(byte<<1)|bits[i+j]
        data_bytes.append(byte)

    marker = b"$bpg0"
    marker_index=data_bytes.find(marker)
    if marker_index!=-1:
        data_bytes=data_bytes[:marker_index]

    with open(dst, "wb") as f:
        f.write(data_bytes)

    print(f"file successfully reconstructed as {dst}")

# we are going to start by assuming the target file is a PNG then move forward with other media types 
def main():
    target_file = select_file("target file")    
    file_to_embed = select_file("sensitive information")
    if(target_file=="" or file_to_embed==""):
        print("null file paths found")
        exit(1)
    
    secret_bytes=file_to_bytes(file_to_embed)

    encode(target_file,secret_bytes,os.path.join(os.path.dirname(os.path.abspath(__file__)),"encoded.png"))
    decode(os.path.join(os.path.dirname(os.path.abspath(__file__)),"encoded.png"),os.path.join(os.path.dirname(os.path.abspath(__file__)),"reconstructed"))
    
    return

if __name__== "__main__":
    main() 