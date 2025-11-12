import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
import argparse
from PIL import Image

LOSSLESS_TYPES=["wav","png"]

# mapping for file signatures
magic_numbers = {
    "pdf": bytes.fromhex("255044462d"),
    "png": bytes.fromhex("89504e470d0a1a0a"),
    "gz": bytes.fromhex("1f8b"),
    "wav": bytes.fromhex("524946460000000057415645")
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
    ok, filetype = verify_lossless(src)
    if not ok:
        print(f"Error: target file must be a lossless type (wav/png), chosen type is '{filetype}'")
        exit(1)
    
    sensitive_info = select_file("sensitive information")
    if(src=="" or sensitive_info==""):
        print("null file paths found")
        exit(1)

    dst=os.path.join(os.path.dirname(os.path.abspath(__file__)),"encoded."+filetype)
    
    if filetype=="png":
        encode_png(src,sensitive_info,dst)
    elif filetype=="wav":
        encode_wav(src,sensitive_info,dst)
    else:
        exit(1)
# snip here


def encode_png(src,sensitive_info,dst):

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
    enc_img = Image.fromarray(array.astype('uint8'))
    enc_img.save(dst)
    print("Image successfully encoded")
    print((int)(size/8),"bytes encoded")
    return 

def encode_wav(src,dst):
    print(f"source: {src}/ndestination: {dst}")
    return 


def decode():
    src = select_file("File to decode")    
    if(src==""):
        print("null file path selected")
        exit(1)

    ok, filetype = verify_lossless(src)
    if not ok:
        print(f"Error: source file must be a lossless type (wav/png), chosen type is '{filetype}'")
        exit(1)

    dst=os.path.join(os.path.dirname(os.path.abspath(__file__)),"reconstructed")

    if filetype=="png":
        decode_png(src,dst)
    elif filetype=="wav":
        decode_wav(src,dst)
    else:
        print("decode not possible for provided file format")

def decode_png(src,dst):
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

    magic=extract_magic(data_bytes[:12]) # calls extract_magic to determine the recovered file type
    dst= dst+"."+magic

    with open(dst, "wb") as f:
        f.write(data_bytes)

    print(f"file successfully reconstructed as {dst}")

def decode_wav(src,dst):
    print(f"source: {src}/ndestination: {dst}")
    return

def verify_lossless(file_path):
    if file_path=="": # if file_path is null
        return False,""
    with open(file_path, "rb") as f:
        header = f.read(12)
    filetype = extract_magic(header)
    return filetype in LOSSLESS_TYPES, filetype

# will return the embedded file type based on magic bytes, returns .txt if no matching header found
def extract_magic(header):
    for filetype, signature in magic_numbers.items():
        if header.startswith(signature):
            return filetype
        if filetype=="wav": #special condition with wav format
            if (header[:4]==signature[:4] and header[8:12]==signature[8:12]):
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