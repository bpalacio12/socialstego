import base64
import tkinter as tk
from tkinter import filedialog

def select_files():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_paths = filedialog.askopenfilenames(title="Select files to encode")
    return list(file_paths)

def main():
    files = select_files()
    for file_path in files:
        with open(file_path, "rb") as f:
            file_data = f.read()
            encoded_data = base64.b64encode(file_data).decode("utf-8")
            print(f"Encoded {file_path}: {encoded_data}")

    return

if __name__== "__main__":
    main() 