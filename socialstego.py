# SocialStego - A new steganography tool for today's social media landscape
# Developed by ParaIIeI (Branden Palacio)
# current release V 0.8 
# 12/2025

import tkinter as tk
from tkinter import filedialog
import os
import numpy as np
import argparse
import soundfile as sf
import discord
import json
import binascii
import warnings
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

# Static reference global lists
LOSSLESS_TYPES=["wav","png"]
SOCIAL_LIST=["DISCORD","REDDIT","SOUNDCLOUD","X"]
PNG_ALLOWED_MODES= {"RGB", "RGBA"}

# Static reference header field sizes 
HEADER_SIZE_BITS=32                 # Denotes the size of the payload data, does not change if the file is encrypted 
HEADER_BIT_COUNT=2                  # Denotes the number of bits to encode per pixel/frame of the source file
HEADER_FLAGS=2                      # References the number of bits used for flags that denote encryption or compression of the encoded data
HEADER_CHECKSUM=12                  # Number of bits attributed to the checksum of the encoded data
HEADER_SIZE=48                      # Protocol header size for the required header fields

HEADER_ENCRYPTED_KEY_SIZE=256       # Size of the encrypted key (AES 256) either 256 bits/32 bytes when unencrypted or 256 bytes if encrypted with RSA pub key
HEADER_IV_SIZE=16                   # Size of the IV for encryption, IV is sent along with the encrypted data when encoded

# Social Media reference values for social media selection``
DISCORD_REF=1
REDDIT_REF=2
SOUNDCLOUD_REF=3

# Prints banner to screen during program execution
def print_banner():
    print(
    """
  /$$$$$$                      /$$           /$$          /$$$$$$   /$$                                  
 /$$__  $$                    |__/          | $$         /$$__  $$ | $$                                  
| $$  \__/  /$$$$$$   /$$$$$$$ /$$  /$$$$$$ | $$        | $$  \__//$$$$$$    /$$$$$$   /$$$$$$   /$$$$$$ 
|  $$$$$$  /$$__  $$ /$$_____/| $$ |____  $$| $$ /$$$$$$|  $$$$$$|_  $$_/   /$$__  $$ /$$__  $$ /$$__  $$
 \____  $$| $$  \ $$| $$      | $$  /$$$$$$$| $$|______/ \____  $$ | $$    | $$$$$$$$| $$  \ $$| $$  \ $$
 /$$  \ $$| $$  | $$| $$      | $$ /$$__  $$| $$         /$$  \ $$ | $$ /$$| $$_____/| $$  | $$| $$  | $$
|  $$$$$$/|  $$$$$$/|  $$$$$$$| $$|  $$$$$$$| $$        |  $$$$$$/ |  $$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$/
 \______/  \______/  \_______/|__/ \_______/|__/         \______/   \___/   \_______/ \____  $$ \______/ 
                                                                                      /$$  \ $$          
                                                                                     |  $$$$$$/          
                                                                                      \______/           
    """
    )

# mapping for file signatures
magic_numbers = {
    "pdf": bytes.fromhex("255044462d"),
    "png": bytes.fromhex("89504e470d0a1a0a"),
    "gz": bytes.fromhex("1f8b"),
    "wav": bytes.fromhex("524946460000000057415645")
}

# loads the config file supplied in the same directory with name config.json to be used for social media api key extraction
def load_config(path="config.json"):
    config_path=Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    
    with open(config_path, "r",encoding="utf-8") as f:
        return json.load(f)
    
# Function for setting the token and channel for the selected social media platform used for distribution
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
# Also specify files, output file, and social media to post to
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
    parser.add_argument("--encrypt",required=False,action="store_true",help="Enable payload encryption (AES + recipients private key)")

    args=parser.parse_args()

    # File specification changes based on encrypt/decrypt mode
    if args.encode:
        if args.files and len(args.files) !=2:
            parser.error("Encoding requires -f <source> <secret_info> (2 files)")

    if args.decode:
        if args.files and len(args.files) !=1:
            parser.error("Decode requires -f <encoded file> (1 file)")

    return args

# Uses the tkinter interface to provide the user with the ability to select the desired files if none are specified in terminal
def select_file(title):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    return filedialog.askopenfilename(initialdir=os.path.expanduser("~/Documents"),title=title)

# Convert the given file into a bitstream for the encoding process
def file_to_bits(file_path):
    with open(file_path, "rb") as f:
        for byte in f.read():
            for i in range(7,-1,-1):
                yield(byte>>i)&1

# Helper function to convert byte sequence to a bitstream
def bytes_to_bits(byte_seq):
    bits=[]
    for b in byte_seq:
        for i in reversed(range(8)):
            bits.append((b>>i)&1)
    return bits

# Helper function to convert bit stream to corresponding integer (used for debugging)
def bits_to_int(bits):
    value=0
    for b in bits:
        value=(value<<1) | b
    return value

# Helper function for converting bitstream into bytestream
def bits_to_bytes(bits):
    return bytes(
        sum((bit << (7 - j)) for j, bit in enumerate(bits[i:i+8]))
        for i in range(0, len(bits), 8)
    )

# when the 'encrypt' flag is specified, this function will run through the process
# of generating a random aes key, random initialization vector, and encrypts the 
# payload bytes (being the 'sensitive information'). Additionally, the AES key is
# encrypted using the recipient's public key solidifying the hybrid encryption scheme.
# Once complete returns both the encrypted AES key and the encrypted payload data
def encrypt_payload(data_bits):
    payload_bytes=bytes(bits_to_bytes(data_bits))
    aes_key=os.urandom(32)
    iv=os.urandom(16)

    with open("example_rsa_key_pub.pem", "rb") as f:
        public_key=serialization.load_pem_public_key(f.read())
    
    # declares the symmetric encryption cipher and the encryption mode
    cipher=Cipher(algorithms.AES(aes_key),modes.OFB(iv)) 
    encryptor=cipher.encryptor() # encryptor object 
    encrypted_bytes=encryptor.update(payload_bytes)+encryptor.finalize() # encrypts payload

    # encrypts the aes encryption key using the recipient's public key
    encrypted_key_bytes=public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_key_bits=bytes_to_bits(encrypted_key_bytes)
    encrypted_data_bits=bytes_to_bits(encrypted_bytes)

    # prepends the IV used for AES to the encrypted bytes to allow decryption for recipient
    iv_bits = bytes_to_bits(iv)
    encrypted_data_bits=iv_bits+encrypted_data_bits

    return encrypted_key_bits, encrypted_data_bits

# builds the payload to be encoded into the source file, generating the required
# header [size bytes][bit count][flags][checksome][data]
# if encrypted flag is set to True, will encrypt the data payload data and prepend
# the payload data with the encrypted aes key and the IV used in encryption
def build_payload_bits(file_path,bit_count,encrypt):
    data_bits=list(file_to_bits(file_path))
    size_bytes = len(data_bits) // 8

    # encoded data size header
    size_header= [(size_bytes >> i) & 1 for i in range(HEADER_SIZE_BITS-1,-1,-1)]

    # encoded bit count header
    bc_map={1:0b00,2:0b01,3:0b10,4:0b11}
    bit_count_header=[(bc_map[bit_count]>>i) & 1 for i in [1,0]]

    # 2-bit flags compressed & encrypted
    compressed=False
    encrypted=encrypt
    flag_value= (int(compressed)<<1) | int(encrypted)
    flag_header= [(flag_value >> i) & 1 for i in range(HEADER_FLAGS-1,-1,-1)]

    # if encryption flag is True
    if encrypt:
        encrypted_key_bits,data_bits = encrypt_payload(data_bits)
        data_bits=encrypted_key_bits+data_bits

    #checksum bits
    crc16=binascii.crc_hqx(bytes(data_bits),0)
    checksum=[(crc16>>i)&1 for i in range(HEADER_CHECKSUM-1,-1,-1)]

    return size_header+bit_count_header+flag_header+checksum+data_bits

# Top level encode function first verifies the source and sensitive infor files and
# file types, and identifies the destination for the encoded source file to be saved
# Then based on the source file type, will run through the encoding procedures for 
# that source file file-type
def encode(src,sensitive_info,dst,encoding_bits,encrypt):
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

    if encrypt:
        print("Encryption mode specified")

    # execute the encode function based on the source file type
    if filetype=="png":
        encode_png(src,sensitive_info,dst,encoding_bits,encrypt)
    elif filetype=="wav":
        encode_wav(src,sensitive_info,dst,encoding_bits,encrypt)
    else:
        exit(1)
    return dst

# Function for encoding the data from the 'sensitive_info' file into the source file
# and saving this information into the specified dsetination. Functionality changes
# based on the specified bitcount and encryption flag when executed from terminal
def encode_png(src,sensitive_info,dst,bit_count,encrypt):
    data_bits=build_payload_bits(sensitive_info,bit_count,encrypt)
    img=Image.open(src, 'r')

    # if the png type is not that of RGB or RGBA will convert to RGB for encoding purposes
    # Types not included in PNG_ALLOWED_MODES are not supported without conversion
    if img.mode not in PNG_ALLOWED_MODES:
        img = img.convert("RGB")

    # mode is necessary for determining pixel write capabilities and saving 
    if img.mode=='RGB':
        n=3
    elif img.mode=='RGBA':
        n=4
    else:
        print(img.mode)
        raise ValueError("Unsuported Image mode")
    
    width,height=img.size
    array=np.array(list(img.getdata()))


    # specifies the available encoding space in the source file and the attempted
    # size of encoded data
    total_pixels=array.size//n
    capacity_bits=total_pixels*3 * bit_count
    print(f"Encoding capacity of PNG: {(capacity_bits//8)-(HEADER_SIZE//8)} bytes")
    print(f"Attempting to encode: {len(data_bits)//8} bytes")

    if len(data_bits)>capacity_bits:
        raise ValueError("Not enough space in the PNG to hide the data - consider compression")

    bit_gen= iter(data_bits)

    # because the recipient will not be able to determine bit-count without the header
    # extraction, the header will always be encoded with 1-bit LSB encoding
    for p in range(HEADER_SIZE//3):
        for q in range(0,3):
            try:
                array[p][q]=(array[p][q] & ~1) | next(bit_gen) 
            except StopIteration:
                break

    # once the header is written, the payload data can be written to the source
    # file using the specified bit-count from the terminal
    for p in range(HEADER_SIZE//3,total_pixels):
        for q in range(0,3):
            for b in range(bit_count):    
                try:
                    array[p][q]=(array[p][q] & ~(1<<b)) | (next(bit_gen) <<b)
                except StopIteration:
                    break

    # shape new array with encoded information and save to specified destination
    array=array.reshape(height,width,n)
    enc_img = Image.fromarray(array.astype('uint8'))
    enc_img.save(dst)
    print("PNG successfully encoded")
    print(f"{len(data_bits)//8} total bytes written")
    return 


# This function will encode sensitive information into a WAV file using
# LSB steganography. Starts by loading the wav file as 16-bit samples 
# If stareo, will use the first channel. Functionality changes based 
# on the specified bitcount and encryption flag when executed from terminal
def encode_wav(src,sensitive_info,dst,bit_count,encrypt):
    samples, samplerate=sf.read(src,dtype='int16')

    # if stereo, pick first channel 
    if samples.ndim > 1:
        samples_to_hide=samples[:,0].copy()
    else:
        samples_to_hide=samples.copy()
    
    # constuct the header and payload bits to be encoded
    data_bits=build_payload_bits(sensitive_info,bit_count,encrypt)
    data_capacity= len(samples_to_hide)*bit_count

    print(f"Encoding capacity of WAV file: {data_capacity//8} bytes")
    print(f"Attempting to encode: {len(data_bits)//8} bytes")

    # verifies if there is enough audio data to hide the message
    if len(data_bits) > data_capacity:

        print("Not enough audio data to hide this message")
        exit(2)
    
    bit_gen = iter(data_bits)

    # start by encoding protocol header with 1-bit LSB encoding
    for i in range(HEADER_SIZE):
        try:
            next_bit=next(bit_gen)
        except StopIteration:
            break
        samples_to_hide[i] = (samples_to_hide[i] & ~1) | next_bit 

    # once header is encoded, proceed to encode the payload data with specified bit-count
    for i in range(HEADER_SIZE,len(samples_to_hide)):
        sample=samples_to_hide[i]
        for b in range(bit_count):
            try:
                next_bit=next(bit_gen)
            except StopIteration:
                break
        
            sample=(sample & ~(1<<b)) | (next_bit <<b)
        samples_to_hide[i] = sample
    
    # if stereo, put modified channel back into samples array
    if samples.ndim > 1:
        encoded_samples=samples.copy()
        encoded_samples[:,0] = samples_to_hide
    else:
        encoded_samples=samples_to_hide

    sf.write(dst,encoded_samples,samplerate, subtype='PCM_16')

    print("WAV successfully encoded")
    print(f"{len(data_bits)//8} total bytes written")
    return 

# Top level function for posting encoded file directly to social media platforms, will extract necessary tokens and keys from the 
# associated config.json file in the same directory as the application and will call the associated social media function based
# on the social media type specified at the terminal
# LIMITATION: currently discord is the only supported social media posting site will expand in the future
def post_social(dst):
    config=load_config()
    token,channel_id = set_token_channel(config,1)
    discord_post(token,channel_id,dst)
    
# Function that performs the process of logging into Discord using the associated token and channel_id. Then
# posts the newly created encoded file along with a user generated message to accompany the post
def discord_post(token,channel_id,dst):
    intents=discord.Intents.default()
    client=discord.Client(intents=intents)
    print(dst)
    @client.event
    async def on_ready():
        print(f"logged in as {client.user}")
        message=input("Message to accompany post: ")
        channel = client.get_channel(channel_id)
        if channel:
            await channel.send(content=message,file=discord.File(dst))
            print(f"Message sent to channel {channel_id}")
        else:
            print(f"channel with ID: {channel_id}, not found")
            return
        await client.close()
    client.run(token)

# Top level decode function starts by determining if the source file is defined and is of the correct file type format, also ensuring that the 
# destination is specified for the extracted data to be saved to. Once all files are verified, calls the assoicated decoding function based on 
# the file type of the source file
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

    # calls the correct decoding funciton based on the source file file-type
    if filetype=="png":
        decode_png(src,dst)
    elif filetype=="wav":
        decode_wav(src,dst)
    else:
        print("decode not possible for provided file format")

# When decoding a target file, this function will extract the header values as
# defined by the custom protocol used to encode information into the source file
# returning an array of variables that reference the header values of the 
# encoded data
def parse_header_bits(header):
    # starts by verifying the header size is correct raising error if not
    if len(header)!=HEADER_SIZE:
        print(len(header))
        raise ValueError("Header size is not expected value")
    
    size_bits = header[:HEADER_SIZE_BITS]
    bit_count_bits = header[HEADER_SIZE_BITS:HEADER_SIZE_BITS+HEADER_BIT_COUNT]
    flag_bits = header[HEADER_SIZE_BITS+HEADER_BIT_COUNT:HEADER_SIZE_BITS+HEADER_BIT_COUNT+HEADER_FLAGS]
    checksum_bits = header[HEADER_SIZE_BITS+HEADER_BIT_COUNT+HEADER_FLAGS:HEADER_SIZE_BITS+HEADER_BIT_COUNT+HEADER_FLAGS+HEADER_CHECKSUM]

    # get payload size in bytes
    payload_size_bytes=bits_to_int(size_bits) 

    # get bit count specifier
    rev_bc_map = {0b00: 1, 0b01: 2, 0b10: 3, 0b11: 4}
    bit_count = rev_bc_map[bits_to_int(bit_count_bits)]

    # get Flag integer and extract flag values
    flags_value=bits_to_int(flag_bits) 
    compressed = (flags_value >> 1) & 1
    encrypted = flags_value &1

    # get 12 bit checksum
    checksum=bits_to_int(checksum_bits)

    to_return={
        "payload_size": payload_size_bytes,
        "bit_count":bit_count,
        "compressed": bool(compressed),
        "encrypted":bool(encrypted),
        "checksum":checksum
    }
    return to_return 

# If the paylaod was identified as being encrypted, this function is called
# with the encrypted AES_key and encrypted payload as parameters. The recient's
# private key is loaded and used to decrypt the appended AES key, then the AES
# key is used to decrypt the payload and returning the decrypted bits
def decrypt_payload(encrypted_key_bits,encrypted_data_bits):
    encrypted_key_bytes=bits_to_bytes(encrypted_key_bits)
    encrypted_data_bytes=bits_to_bytes(encrypted_data_bits)

    with open("example_rsa_key","rb") as f:
        private_key=serialization.load_pem_private_key(f.read(),password=None)
    
    # decrypt the AES key using recipient's private key
    aes_key=private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # reconstrct the IV and the ciphertext from the provided data
    iv =encrypted_data_bytes[:16]
    ciphertext=encrypted_data_bytes[16:]

    # decrypt the payload using the decrypted AES key and IV
    cipher=Cipher(algorithms.AES(aes_key),modes.OFB(iv))
    decryptor=cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext)+decryptor.finalize()

    decrypted_bits = bytes_to_bits(decrypted_bytes)
    return decrypted_bits

# Function for extracting sensitive information from a target PNG, starts by
# loading the PNG, extracting the header bits encoded into the source file,
# using this header information to inform the control flow of the program
# and extracting the encoded bits from the source file. The extracte data
# is then saved to a file and available for the recipient to view 
def decode_png(src,dst):
    img=Image.open(src,'r')
    array=np.array(list(img.getdata()))

    # determine number of channels based on image mode
    if img.mode=='RGB':
        n=3
    elif img.mode=='RGBA':
        n=4
    else:
        raise ValueError("Unsupported image mode")

    total_pixels=array.size//n

    # extract header bits first to determine control flow
    header_bits=[]
    for p in range(HEADER_SIZE//3):
        for q in range(0,3):
            header_bits.append(array[p][q] & 1)
            if len(header_bits)==HEADER_SIZE: break
        if len(header_bits)==HEADER_SIZE: break

    # parse header bits to determine payload size, bit count, flags, checksum
    header_vals=parse_header_bits(header_bits)
    bit_count=header_vals["bit_count"]
    if header_vals["encrypted"]:
        payload_size_bits = (HEADER_ENCRYPTED_KEY_SIZE+HEADER_IV_SIZE+header_vals["payload_size"])*8
    else:
        payload_size_bits = header_vals["payload_size"]*8

    # extract payload bits based on header information
    lsb_bits=[]
    for p in range(HEADER_SIZE//3,total_pixels):
        for q in range(0,3):
            for b in range(bit_count):
                lsb_bits.append((array[p][q]>>b) & 1)
                if len(lsb_bits)==payload_size_bits: break
            if len(lsb_bits)==payload_size_bits: break
        if len(lsb_bits)==payload_size_bits: break
    
    # verify checksum of extracted data
    if not verify_checksum(lsb_bits,header_vals["checksum"]):
        warnings.warn("Checksum of extracted file is not consistent with expect value/nExtraction still completed")
    else:
        print("Extracted Checksum consistent with calculated")

    # decrypt payload if necessary
    if header_vals["encrypted"]:
        lsb_bits=decrypt_payload(lsb_bits[:2048],lsb_bits[2048:])
                
    data_bytes=bits_to_bytes(lsb_bits)

    # calls extract_magic to determine the recovered file type
    magic=extract_magic(data_bytes[:12]) 
    dst= dst+"."+magic

    # save file to specified destination
    with open(dst, "wb") as f:
        f.write(data_bytes)

    print(f"file successfully reconstructed as {dst}")

# Function for extracting sensitive information from a target WAV, starts by
# loading the WAV, extracting the header bits encoded in the source file,
# using this header information to inform the control flow of the program
# and extracting the encoded bits from the source file. The extracte data
# is then saved to a file and available for the recipient to view 
def decode_wav(src,dst):
    samples,_ =sf.read(src,dtype='int16')

    # if stereo, pick first channel
    if samples.ndim >1:
        samples_to_read=samples[:,0]
    else:
        samples_to_read=samples

    # extract header bits first to determine control flow
    header_bits = [int(samples_to_read[i] & 1) for i in range(48)]

    # parse header bits to determine payload size, bit count, flags, checksum
    header_vals=parse_header_bits(header_bits)
    bit_count = header_vals["bit_count"]
    payload_size_bytes = header_vals["payload_size"]
    encrypted=header_vals["encrypted"]
    if encrypted:
        payload_size_bits = (payload_size_bytes+HEADER_IV_SIZE+HEADER_ENCRYPTED_KEY_SIZE)*8
    else:
        payload_size_bits = payload_size_bytes * 8

    # extract payload bits based on header information
    lsb_bits = []
    for i in range(HEADER_SIZE, len(samples_to_read)):
        sample = samples_to_read[i]
        for b in range(bit_count):
            lsb_bits.append((sample>>b)&1)
            if len(lsb_bits)==payload_size_bits: break
        if len(lsb_bits)==payload_size_bits: break

    # verify checksum of extracted data
    if not verify_checksum(lsb_bits,header_vals["checksum"]):
        warnings.warn("Checksum of extracted file is not consistent with expect value/nExtraction still completed")
    else:
        print("Extracted Checksum consistent with calculated")

    # decrypt payload if necessary
    if encrypted:
        lsb_bits=decrypt_payload(lsb_bits[:2048],lsb_bits[2048:])

    data_bytes=bits_to_bytes(lsb_bits)

    # calls extract_magic to determine the recovered file type
    magic=extract_magic(data_bytes[:12]) 
    dst=dst+"."+magic

    # save file to specified destination
    with open(dst,"wb") as f:
        f.write(data_bytes)
    
    print(f"File successfully reconstructed as {dst}")    
    return

# Function used to verify the checksum of the extracted information from a
# chosen source file. Returns if the checksum encoded into the 'checksum'
# header of the custom protocol is consistent with the checksum of the 
# extracted data
def verify_checksum(data_bits, expected_checksum):
    crc16=binascii.crc_hqx(bytes(data_bits),0)
    mask=(1<<HEADER_CHECKSUM)-1
    calculated=crc16 & mask
    return calculated==expected_checksum

# This function verifies the file type of the provided source file as being 
# a lossless data type as denoted in the LOSSLESS_TYPES global list
def verify_lossless(file_path):
    if file_path=="": # if file_path is null
        return False,""
    with open(file_path, "rb") as f:
        header = f.read(12)
    filetype = extract_magic(header)
    return filetype in LOSSLESS_TYPES, filetype

# will return the file type based on magic bytes, returns .txt if no matching header found
def extract_magic(header):
    for filetype, signature in magic_numbers.items():
        if header.startswith(signature):
            return filetype
        if filetype=="wav": #special condition with wav format
            if (header[:4]==signature[:4] and header[8:12]==signature[8:12]):
                return filetype
    return "txt"

# Main function controlling the flow of the execution of this program starts
# by parsing the arguments from the command line to determine the mode of 
# execution, files, output file name, bit count, and other flags 
def main():
    print_banner()
    args=parse_args()
    files=args.files or []
    social=args.social or ""
    encoding_bits=args.bit_count or 1
    if args.encode:
        output=args.output or "encoded"
        if len(files):
            dst = encode(files[0],files[1],output,encoding_bits,args.encrypt)
        else:
            dst = encode("","",output,encoding_bits,args.encrypt)
        if not social=="":
            load_config()
            post_social(dst)
    elif args.decode:
        output=args.output or "reconstructed"
        if not social=="":
            # TODO this is where we will extract from social media
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
