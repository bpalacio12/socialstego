import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
import argparse
import soundfile as sf
import discord
import json
from pathlib import Path
from PIL import Image

LOSSLESS_TYPES=["wav","png"]
SOCIAL_LIST=["DISCORD","REDDIT","SOUNDCLOUD"]

TOKEN=""
CHANNEL_ID=""

DISCORD_REF=1
REDDIT_REF=2
SOUNDCLOUD_REF=3

# mapping for file signatures
magic_numbers = {
    "pdf": bytes.fromhex("255044462d"),
    "png": bytes.fromhex("89504e470d0a1a0a"),
    "gz": bytes.fromhex("1f8b"),
    "wav": bytes.fromhex("524946460000000057415645")
}

# loads the config file supplied in the same directory with name config.json
def load_config(path="config.json"):
    config_path=Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    
    with open(config_path, "r",encoding="utf-8") as f:
        return json.load(f)
    
def set_token_channel(config,choice):
    match choice:
        case _ if choice==DISCORD_REF:
            return config["discord"]["bot_token"], int(config["discord"]["channel_id"])
        case _ if choice==REDDIT_REF:
            return
        case _ if choice==SOUNDCLOUD_REF:
            return
        case _:
            print(f"No social media selection was found for chosen selection")
            return

# Argument parsing to determine either encoding or decoding actions 
# Also specify files, output file, and social media to extract from
def parse_args():
    parser=argparse.ArgumentParser(description="Stegonagraphy Encoder/Decoder script")
    # required flags
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-e", "--encode", action="store_true", help="Run in encode mode")
    mode.add_argument("-d", "--decode", action="store_true", help="Run in decode mode")
    
    #optional flags
    parser.add_argument("-f","--files",required=False,nargs='*',help="Files: encode=source secret | decode=encoded")
    parser.add_argument("-o","--output",required=False,help="Output filename")
    parser.add_argument("-s","--social",required=False,choices=SOCIAL_LIST,type=str.upper,help=f"Choose social media: {SOCIAL_LIST}")

    args=parser.parse_args()

    if args.encode:
        if args.files and len(args.files) !=2:
            parser.error("Encoding requires -f <source> <secret_info> (2 files)")

    if args.decode:
        if args.files and len(args.files) !=1:
            parser.error("Decode requires -f <encoded file> (1 file)")

    return args

# Uses the tkinter interface to provide the user with the ability to select the desired files if none are specified
def select_file(title):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    return filedialog.askopenfilename(initialdir=os.path.expanduser("~/Documents"),title=title)

def file_to_bits(file_path):
    with open(file_path, "rb") as f:
        for byte in f.read():
            for i in range(7,-1,-1):
                yield(byte>>i)&1

def build_payload_bits(file_path):
    data_bits=list(file_to_bits(file_path))
    size_bytes = len(data_bits) // 8

    header_bits= [(size_bytes >> i) & 1 for i in range(63,-1,-1)]

    return header_bits+list(data_bits)

def bits_to_int(bits):
    value=0
    for b in bits:
        value=(value<<1) | b
    return value

def bits_to_bytes(bits):
    return bytes(
        sum((bit << (7 - j)) for j, bit in enumerate(bits[i:i+8]))
        for i in range(0, len(bits), 8)
    )

def encode(src,sensitive_info,dst):
    # ensure source file to encode is correct
    if not src:
        src = select_file("target file")    
    ok, filetype = verify_lossless(src)
    if not ok:
        print(f"Error: target file must be a lossless type (wav/png), chosen type is '{filetype}'")
        exit(1)
    
    # ensure sensitive_info file is correct
    if not sensitive_info:
        sensitive_info = select_file("sensitive information")
    if(src=="" or sensitive_info==""):
        print("null file paths found")
        exit(1)

    if not dst:
        dst=os.path.join(os.path.dirname(os.path.abspath(__file__)),"encoded."+filetype)
    else:
        dst=dst.split('.',1)[0]+"."+filetype

    if filetype=="png":
        encode_png(src,sensitive_info,dst)
    elif filetype=="wav":
        encode_wav(src,sensitive_info,dst)
    else:
        exit(1)
    return dst

def encode_png(src,sensitive_info,dst):
    data_bits=build_payload_bits(sensitive_info)

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
    capacity_bits=total_pixels*3

    if len(data_bits)>capacity_bits:
        raise ValueError("Not enough space in the PNG to hide the data - consider compression")

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
    print("PNG successfully encoded")
    print(f"{len(data_bits)//8} total bytes written [8-byte header][sensitive data]")
    return 

def encode_wav(src,sensitive_info,dst):
    samples, samplerate=sf.read(src,dtype='int16')

    # if stereo, pick first channel (or interleave if desired)
    if samples.ndim > 1:
        samples_to_hide=samples[:,0].copy()
    else:
        samples_to_hide=samples.copy()
    
    data_bits=build_payload_bits(sensitive_info)

    if len(data_bits) > len(samples_to_hide):
        raise ValueError("Not enough audio data to hide this message")
    
    samples_to_hide[:len(data_bits)] = (samples_to_hide[:len(data_bits)] & ~1) | np.array(data_bits,dtype=np.int16)
    
    if samples.ndim > 1:
        encoded_samples=samples.copy()
        encoded_samples[:,0] = samples_to_hide
    else:
        encoded_samples=samples_to_hide

    sf.write(dst,encoded_samples,samplerate, subtype='PCM_16')

    print("WAV successfully encoded")
    print(f"{len(data_bits)//8} total bytes written [8-byte header][sensitive data]")
    return 

def save_file(dst,file):
    
    return

def post_social(dst):
    config=load_config()
    TOKEN,CHANNEL_ID = set_token_channel(config,1)
    discord_post(TOKEN,CHANNEL_ID,dst)
    
def discord_post(TOKEN, CHANNEL_ID,dst):
    intents=discord.Intents.default()
    client=discord.Client(intents=intents)
    print(dst)
    @client.event
    async def on_ready():
        print(f"logged in as {client.user}")
        channel = client.get_channel(CHANNEL_ID)
        if channel:
            await channel.send(content="This is a test",file=discord.File(dst))
            print(f"Message sent to channel {CHANNEL_ID}")
        else:
            print(f"channel with ID: {CHANNEL_ID}, not found")
            return
        await client.close()
    client.run(TOKEN)

def decode(src,dst):
    # ensure correct source file
    if not src:
        src = select_file("File to decode")    
    if(src==""):
        print("null file path selected")
        exit(1)
    ok, filetype = verify_lossless(src)
    if not ok:
        print(f"Error: source file must be a lossless type (wav/png), chosen type is '{filetype}'")
        exit(1)

    if not dst:
        dst=os.path.join(os.path.dirname(os.path.abspath(__file__)),"reconstructed")
    else:
        dst=dst.split('.',1)[0]

    if filetype=="png":
        decode_png(src,dst)
    elif filetype=="wav":
        decode_wav(src,dst)
    else:
        print("decode not possible for provided file format")

def decode_png(src,dst):
    img=Image.open(src,'r')
    array=np.array(list(img.getdata()))
    # bits=[]

    if img.mode=='RGB':
        n=3
    elif img.mode=='RGBA':
        n=4
    else:
        raise ValueError("Unsupported image mode")

    total_pixels=array.size//n

    lsb_bits=[]
    for p in range(total_pixels):
        for q in range(0,3):
            lsb_bits.append(array[p][q] & 1)

    header_bits = lsb_bits[:64]
    size_bytes = int(bits_to_int(header_bits))
    stored_data_bits = size_bytes*8

    data_bits=lsb_bits[64:64+stored_data_bits]
    data_bytes=bits_to_bytes(data_bits)

    magic=extract_magic(data_bytes[:12]) # calls extract_magic to determine the recovered file type
    dst= dst+"."+magic

    with open(dst, "wb") as f:
        f.write(data_bytes)

    print(f"file successfully reconstructed as {dst}")

def decode_wav(src,dst):
    samples,_ =sf.read(src,dtype='int16')

    if samples.ndim >1:
        samples_to_read=samples[:,0]
    else:
        samples_to_read=samples

    lsb_bits=[int(s&1) for s in samples_to_read]

    header_bits=lsb_bits[:64]
    size_bytes= int(bits_to_int(header_bits))
    print(size_bytes)
    stored_data_bits = size_bytes*8

    data_bits=lsb_bits[64:64+stored_data_bits]
    data_bytes=bits_to_bytes(data_bits)

    magic=extract_magic(data_bytes[:12]) # calls extract_magic to determine the recovered file type
    dst=dst+"."+magic

    with open(dst,"wb") as f:
        f.write(data_bytes)
    
    print(f"File successfully reconstructed as {dst}")    
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
    load_config()
    files=args.files or []
    social=args.social or ""
    if args.encode:
        output=args.output or "encoded"
        if len(files):
            dst = encode(files[0],files[1],output)
        else:
            dst = encode("","",output)
        if not social=="":
            post_social(dst)
    elif args.decode:
        output=args.output or "reconstructed"
        if not social=="":
            # this is where we will extract from social
            print("Not currently supported")
            return
        else:
            if len(files):
                decode(files[0],output)
            else:
                decode("",output)    
    return

if __name__== "__main__":
    main() 