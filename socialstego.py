import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
import argparse
from PIL import Image

# mapping for file signatures
magic_numbers = {
    "pdf": bytes.fromhex("255044462d"),
    "png": bytes.fromhex("89504e470d0a1a0a"),
    "gzip": bytes.fromhex("1f8b")
}

# Argument parsing to determine either encoding or decoding actions
def parse_args():
    parser=argparse.ArgumentParser(description="Stegonagraphy Encoder/Decoder script")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encode", action="store_true", help="Run in encode mode")
    group.add_argument("-d", "--decode", action="store_true", help="Run in decode mode")
    return parser.parse_args()

# Uses the tkinter interface to provide the user withthe ability to select the desired files 
def select_file(title):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    return filedialog.askopenfilename(initialdir=os.path.expanduser("~/Documents"),title=title)

def file_to_bits(file_path):
    with open(file_path, "rb") as f:
        for byte in f.read():
            for i in range(7,-1,-1):
                yield(byte>>i)&1

def marker_bits():
    marker = b"$bpg0"
    for byte in marker:
        for i in range(7,-1,-1):
            yield(byte>>i)&1

def encode():
    src = select_file("target file")    
    sensitive_info = select_file("sensitive information")
    if(src=="" or sensitive_info==""):
        print("null file paths found")
        exit(1)
    
    dst=os.path.join(os.path.dirname(os.path.abspath(__file__)),"encoded.png")
    data=file_to_bits(sensitive_info)

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

    # bit_gen= (bit for bit in list(data)+list(marker_bits()))s
    # size=len(list(bit_gen))

    data_bits=list(data)+list(marker_bits())
    size=len(data_bits)
    bit_gen= iter(data_bits)

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
    print((int)(size/8),"bytes encoded")

def decode():
    src = select_file("File to decode")    
    if(src==""):
        print("null file path selected")
        exit(1)
    dst=os.path.join(os.path.dirname(os.path.abspath(__file__)),"reconstructed")

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

    magic=extract_magic(data_bytes[:10]) # calls extract_magic to determine the recovered file type
    dst= dst+"."+magic

    with open(dst, "wb") as f:
        f.write(data_bytes)

    print(f"file successfully reconstructed as {dst}")

# will return the embedded file type based on magic bytes, returns .txt if no matching header found
def extract_magic(header):
    print(header)
    for filetype, signature in magic_numbers.items():
        if header.startswith(signature):
            return filetype
    return "txt"

# we are going to start by assuming the target file is a PNG then move forward with other media types 
def main():
    args=parse_args()
    if args.encode:
        encode()
    elif args.decode:
        decode()    
    return

if __name__== "__main__":
    main() 