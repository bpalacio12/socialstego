import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
import argparse
import soundfile as sf
import discord
import json
import binascii
from pathlib import Path
from PIL import Image

LOSSLESS_TYPES=["wav","png"]
SOCIAL_LIST=["DISCORD","REDDIT","SOUNDCLOUD"]
HEADER_SIZE_BITS=32
HEADER_BIT_COUNT=2
HEADER_FLAGS=2
HEADER_CHECKSUM=12
HEADER_SIZE=48

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
    parser.add_argument("-b","--bit-count",required=False,type=int,choices=range(1,5),help="User decision for the number of bits to encode within the original file")

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

# TODO: create functions to compress and encrypt 

def build_payload_bits(file_path,bit_count):
    data_bits=list(file_to_bits(file_path))
    size_bytes = len(data_bits) // 8

    # encoded data size header
    size_header= [(size_bytes >> i) & 1 for i in range(HEADER_SIZE_BITS-1,-1,-1)]

    # encoded bit count header
    bc_map={1:0b00,2:0b01,3:0b10,4:0b11}
    bit_count_header=[(bc_map[bit_count]>>i) & 1 for i in [1,0]]

    # 2-bit flags compressed & encrypted
    compressed=False
    encrypted=False
    flag_value= (int(compressed)<<1) | int(encrypted)
    flag_header= [(flag_value >> i) & 1 for i in range(HEADER_FLAGS-1,-1,-1)]

    #checksum bits
    crc16=binascii.crc_hqx(bytes(data_bits),0)
    checksum=[(crc16>>i)&1 for i in range(HEADER_CHECKSUM-1,-1,-1)]

    return size_header+bit_count_header+flag_header+checksum+data_bits

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

def encode(src,sensitive_info,dst,encoding_bits):
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
        encode_png(src,sensitive_info,dst,encoding_bits)
    elif filetype=="wav":
        encode_wav(src,sensitive_info,dst,encoding_bits)
    else:
        exit(1)
    return dst

def encode_png(src,sensitive_info,dst,bit_count):
    data_bits=build_payload_bits(sensitive_info,bit_count)

    # For DEBUGGING
    # size_bits = data_bits[:32]
    # bit_count_bits = data_bits[32:34]
    # flags_bits = data_bits[34:36]
    # checksum_bits = data_bits[36:48]

    # print("Payload size bits: ", ''.join(str(b) for b in size_bits),bits_to_int(size_bits))
    # print("Bit count bits:    ", ''.join(str(b) for b in bit_count_bits),bits_to_int(bit_count_bits))
    # print("Flags bits:        ", ''.join(str(b) for b in flags_bits),bits_to_int(flags_bits))
    # print("Checksum bits:     ", ''.join(str(b) for b in checksum_bits),bits_to_int(checksum_bits))

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
    capacity_bits=total_pixels*3 * bit_count

    print(f"Encoding capacity of wave file: {capacity_bits//8} bytes")
    print(f"Attempting to encode: {len(data_bits)//8} bytes")

    if len(data_bits)>capacity_bits:
        raise ValueError("Not enough space in the PNG to hide the data - consider compression")

    bit_gen= iter(data_bits)

    for p in range(HEADER_SIZE//3):
        for q in range(0,3):
            try:
                array[p][q]=(array[p][q] & ~1) | next(bit_gen) 
            except StopIteration:
                break

    for p in range(HEADER_SIZE//3,total_pixels):
        for q in range(0,3):
            for b in range(bit_count):    
                try:
                    array[p][q]=(array[p][q] & ~(1<<b)) | (next(bit_gen) <<b)
                except StopIteration:
                    break

    array=array.reshape(height,width,n)
    enc_img = Image.fromarray(array.astype('uint8'))
    enc_img.save(dst)
    print("PNG successfully encoded")
    print(f"{len(data_bits)//8} total bytes written")
    return 

def encode_wav(src,sensitive_info,dst,bit_count):
    samples, samplerate=sf.read(src,dtype='int16')

    # if stereo, pick first channel (or interleave if desired)
    if samples.ndim > 1:
        samples_to_hide=samples[:,0].copy()
    else:
        samples_to_hide=samples.copy()
    
    data_bits=build_payload_bits(sensitive_info,bit_count)
    data_capacity= ((len(samples_to_hide)-HEADER_SIZE)*bit_count + HEADER_SIZE)

    print(f"Encoding capacity of WAV file: {data_capacity//8} bytes")
    print(f"Attempting to encode: {len(data_bits)//8} bytes")

    if len(data_bits) > data_capacity:

        print("Not enough audio data to hide this message")
        exit(2)
    
    bit_gen = iter(data_bits)

    for i in range(HEADER_SIZE):
        try:
            next_bit=next(bit_gen)
        except StopIteration:
            break
        samples_to_hide[i] = (samples_to_hide[i] & ~1) | next_bit 

    for i in range(HEADER_SIZE,len(samples_to_hide)):
        sample=samples_to_hide[i]
        for b in range(bit_count):
            try:
                next_bit=next(bit_gen)
            except StopIteration:
                break
        
            sample=(sample & ~(1<<b)) | (next_bit <<b)
        samples_to_hide[i] = sample
    
    if samples.ndim > 1:
        encoded_samples=samples.copy()
        encoded_samples[:,0] = samples_to_hide
    else:
        encoded_samples=samples_to_hide

    sf.write(dst,encoded_samples,samplerate, subtype='PCM_16')

    print("WAV successfully encoded")
    print(f"{len(data_bits)//8} total bytes written")
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

def parse_header_bits(header):
    if len(header)!=HEADER_SIZE:
        print(len(header))
        raise ValueError("Header size is not expected value")
    
    size_bits = header[:HEADER_SIZE_BITS]
    bit_count_bits = header[HEADER_SIZE_BITS:HEADER_SIZE_BITS+HEADER_BIT_COUNT]
    flag_bits = header[HEADER_SIZE_BITS+HEADER_BIT_COUNT:HEADER_SIZE_BITS+HEADER_BIT_COUNT+HEADER_FLAGS]
    checksum_bits = header[HEADER_SIZE_BITS+HEADER_BIT_COUNT+HEADER_FLAGS:HEADER_SIZE_BITS+HEADER_BIT_COUNT+HEADER_FLAGS+HEADER_CHECKSUM]

    payload_size_bytes=bits_to_int(size_bits) # payload size in bytes

    rev_bc_map = {0b00: 1, 0b01: 2, 0b10: 3, 0b11: 4}
    bit_count = rev_bc_map[bits_to_int(bit_count_bits)] # bit count specifier

    flags_value=bits_to_int(flag_bits) # Flag intager

    checksum=bits_to_int(checksum_bits) # checksum

    compressed = (flags_value >> 1) & 1
    encrypted = flags_value &1

    to_return={
        "payload_size": payload_size_bytes,
        "bit_count":bit_count,
        "compressed": bool(compressed),
        "encrypted":bool(encrypted),
        "checksum":checksum
    }
    return to_return 

def decode_png(src,dst):
    img=Image.open(src,'r')
    array=np.array(list(img.getdata()))

    if img.mode=='RGB':
        n=3
    elif img.mode=='RGBA':
        n=4
    else:
        raise ValueError("Unsupported image mode")

    total_pixels=array.size//n

    header_bits=[]
    for p in range(HEADER_SIZE//3):
        for q in range(0,3):
            header_bits.append(array[p][q] & 1)
            if len(header_bits)==HEADER_SIZE: break
        if len(header_bits)==HEADER_SIZE: break

    header_vals=parse_header_bits(header_bits)
    bit_count=header_vals["bit_count"]
    payload_size_bits = header_vals["payload_size"]*8

    lsb_bits=[]
    for p in range(HEADER_SIZE//3,total_pixels):
        for q in range(0,3):
            for b in range(bit_count):
                lsb_bits.append((array[p][q]>>b) & 1)
                if len(lsb_bits)==payload_size_bits: break
            if len(lsb_bits)==payload_size_bits: break
        if len(lsb_bits)==payload_size_bits: break
                
    data_bytes=bits_to_bytes(lsb_bits)

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

    header_bits = [int(samples_to_read[i] & 1) for i in range(48)]

    header_vals=parse_header_bits(header_bits)
    bit_count = header_vals["bit_count"]
    payload_size_bytes = header_vals["payload_size"]
    payload_size_bits = payload_size_bytes * 8

    lsb_bits = []
    # lsb_bits=[int(s&1) for s in samples_to_read]

    # HEADER_SIZE_BITS=lsb_bits[:HEADER_SIZE_BITS]
    # size_bytes= int(bits_to_int(HEADER_SIZE_BITS))
    # print(size_bytes)
    # stored_data_bits = size_bytes*8

    # data_bits=lsb_bits[HEADER_SIZE_BITS:HEADER_SIZE_BITS+stored_data_bits]
    # data_bytes=bits_to_bytes(data_bits)

    for i in range(HEADER_SIZE, len(samples_to_read)):
        sample = samples_to_read[i]

        for b in range(bit_count):
            lsb_bits.append((sample>>b)&1)
            if len(lsb_bits)==payload_size_bits: break
        
        if len(lsb_bits)==payload_size_bits: break

    data_bytes=bits_to_bytes(lsb_bits)

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
    encoding_bits=args.bit_count or 1
    if args.encode:
        output=args.output or "encoded"
        if len(files):
            dst = encode(files[0],files[1],output,encoding_bits)
        else:
            dst = encode("","",output,encoding_bits)
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