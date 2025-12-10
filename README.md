# socialstego
Stego tools for social media enabled covert channels

SocialStego is a tool that was created to leverage the capabilities of LSB steganography to distribute encoded files though social networks such as Discord or X. 

## Table of Contents
- [Functionality](#Functionality)
- [Installation](#Installation)
- [Execution](#Execution)
- [Limitations](#Limitations)

## Functionality
#### Supports both encoding and decoding functionality for LSB encoded PNG and WAV files

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
cd socialstego
pip install -r requirements.txt
```

## Execution 
### file specifier
-f | --files

Example encode:
```bash
python socialstego.py -e -f original.png test.txt​
```
Example decodE:
```bash
python socialstego.py -e -f encoded.wav
```


