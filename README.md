# socialstego
Stego tools for social media enabled covert channels

SocialStego is a tool that was created to leverage the capabilities of LSB steganography to distribute encoded files though social networks such as Discord or X. 

## Functionality
- Supports both encoding and decoding functionality for LSB encoded PNG and WAV files
- File selection from terminal or through Tkinter UI at runtime
- Automated file type identifier to determine control flow and file extension for saved files
- User can specify the LSB bit count to provide granular control over encoding concentration and overall encoding volume
<img width="960" height="720" alt="LSB_bit_count (4)" src="https://github.com/user-attachments/assets/28c19e33-7e39-452e-bb4d-a5711c213dc7" />

- Custom 48 bit encoding protocol
<img width="993" height="698" alt="stegocol" src="https://github.com/user-attachments/assets/44886eb8-3a7e-4825-8bcc-e97d7d0bec32" />

- Hybrid encryption (AES_256 and RSA_2048) capability
- Automated social media posting through inclusion of config.json  


## Installation

clone the repository and install necessary packages:

```bash
git clone https://github.com/bpalacio12/socialstego.git
cd socialstego
pip install -r requirements.txt
```


## Execution 



