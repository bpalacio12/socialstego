# socialstego
Stego tools for social media enabled covert channels

SocialStego is a tool that was created to leverage the capabilities of LSB steganography to distribute encoded files though social networks such as Discord or X. This tool was created for education purposes only and should not actually be used to cause harm. 

## Table of Contents
- [Functionality](#Functionality)
- [Installation](#Installation)
- [Execution](#Execution)
- [Considerations](#Considerations)

## Functionality
#### Supports both encoding and decoding functionality for PNG and WAV files
Example encode:
```bash
python socialstego.py -e​
```
Example decode:
```bash
python socialstego.py -d 
```

#### File selection from terminal or through Tkinter UI at runtime
<img width="719" height="408" alt="image" src="https://github.com/user-attachments/assets/034094b0-489e-4f7f-a263-9eccd24f26db" />

#### Automated file type identifier to determine control flow and file extension for saved files
<img width="346" height="119" alt="Screenshot 2025-12-01 204244" src="https://github.com/user-attachments/assets/3e3ab391-610d-4aea-9c53-875dc3e5ddee" />

#### User can specify the LSB bit count to provide granular control over encoding concentration and overall encoding volume
<img width="960" height="720" alt="LSB_bit_count (4)" src="https://github.com/user-attachments/assets/28c19e33-7e39-452e-bb4d-a5711c213dc7" />

#### Custom 48 bit encoding protocol
<img width="993" height="698" alt="stegocol" src="https://github.com/user-attachments/assets/44886eb8-3a7e-4825-8bcc-e97d7d0bec32" />

#### Hybrid encryption (AES_256 and RSA_2048) capability
<img width="592" height="221" alt="encyption protocol" src="https://github.com/user-attachments/assets/fe03835d-76ad-40f1-bb1c-9809b94daf78" />

#### Automated social media posting through inclusion of config.json  
<img width="508" height="355" alt="Screenshot 2025-12-01 224339" src="https://github.com/user-attachments/assets/1a48f9c8-335e-488f-8ebf-a64f61f9da70" />


## Installation

clone the repository and install necessary packages:

```bash
git clone https://github.com/bpalacio12/socialstego.git
```
Ensure Python 3.11 or later is installed on your system along with Python pip - follow these links for more information:  
Installing Python: https://www.python.org/downloads/release/python-3110/  
Installing pip: https://pip.pypa.io/en/stable/installation/  

It is encouraged to set up a Python virtual environment for this project but it is not necessary, if interested follow this link for more information:
Python Virtual Environment: https://docs.python.org/3/library/venv.html

Once Python and pip are installed, install necessary python packages using the following commands:
```bash
cd socialstego
pip install -r requirements.txt
```
If you are interested in making use of encryption ensure that you have a RSA_2048 generated keypair which can be created with the following commands (ensure you have openssl installed):
```bash
openssl genrsa -out example_rsa_key.pem 2048
openssl rsa -in ./example_rsa_key.pem -pubout -out ./example_rsa_key_pub.pem
```
If you are interested in making use of automated social media automated posting create a valid config.json shown in the 'Social Media Posting' section. Follow the processes here to created a discord bot:  
create discord bot: https://discord.com/developers/docs/intro

the private key should only be held by the recipient, while the public key can be used by anyone interested in sending a message to the recipient.

## Execution 
### File specifier
-f | --files

Example encode:
```bash
python socialstego.py -e -f original.png test.txt​
```
Example decode:
```bash
python socialstego.py -d -f encoded.wav
```

### Output file naming
-o | --output

Example encode:
```bash
python socialstego.py -e -o encoded​
```
Example decode:
```bash
python socialstego.py -d -o extracted
```
Note: The file specifier does not need to be included for the output file, will rely on the logic created in the file type identifier flow.

### Bit count specifier
-b | --bit-count

Example: Only supported in encoding mode
```bash
python socialstego.py -e -b 3 -o encoded​
```
Note: Values range between 1 and 4, default encoding will be LSB 1 

### Encryption

Example: Only supported in encoding mode
```bash
python socialstego.py -e --encrypt
```
Note: in order to implement encryption when encoding you must have an example RSA_2048 public key in the same directory named 'example_rsa_key_pub.pem' If decoding an encrypted payload the associated RSA_2048 private key must be in the project directory and named 'example_rsa_key.pem"


### Social Media Posting

Example: Only supported in encoding mode with Discord specifier - Future sites may be incorporated at a later date
```bash
python socialstego.py -e -s Discord
```
Note: in order to use the automated social media posting flag you must have a seperated config.json present in the project directory formmated as follows:
```json
{
    "discord": {
        "bot_token":<bot_token>,
        "channel_id":<channel_id>
    }
}
```

## Considerations

### Implementing Encryption
In order to guarantee information security, it is important to implement encryption when encoding a carrier file. Without encryption, anyone will be able to extract encoded information whether intended for them or not. 

### Resultant Noise From Encoding
One of the limitations for this current imlementation is the visually identifiable noise of encoded files. The encoding process ends once the final paylaod bit is encoded into the carrier file and as a result leaves a noticable horizontal line where the file is encoded vs. where it is consistent with the original. Additionally, visually inspecting the LSB-half of an encoded file easily reveals the section of a file that is encoded vs. consistent with the original. Lastly, encoding files with an already variable amount of noise will be helpful in reducing the visually identifiable aspect of encoding

<img width="1153" height="562" alt="image" src="https://github.com/user-attachments/assets/653fb3af-c7c7-496b-915f-eba4a3a2498b" />

### Data Throughput 
The amount of data that can be encoded into a file is entirely dependent on the file type and can be loosely calculated using the following equations:
<img width="1115" height="364" alt="image" src="https://github.com/user-attachments/assets/df69358c-db93-4495-91bf-eef3c5cf65a7" />




