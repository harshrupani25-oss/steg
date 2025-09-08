import tkinter as tk
from tkinter import filedialog, messagebox
import cv2
import numpy as np
import os

# Utility Functions
def to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def xor_encrypt(binary_text, key_binary):
    return ''.join(str(int(b) ^ int(key_binary[i % len(key_binary)])) for i, b in enumerate(binary_text))

def hide_message(video_path, secret_message, key, output_path):
    if not os.path.exists(video_path):
        raise FileNotFoundError(f"Video not found: {video_path}")
    if not key:
        raise ValueError("Key cannot be empty.")

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Cannot open video file.")

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    message_bin = to_binary(secret_message) + '1111111111111110'  # delimiter
    key_bin = to_binary(key)
    encrypted_bin = xor_encrypt(message_bin, key_bin)

    bit_index = 0
    total_bits = len(encrypted_bin)

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if bit_index < total_bits:
            flat = frame.flatten()
            for i in range(len(flat)):
                if bit_index >= total_bits:
                    break
                flat[i] = (flat[i] & 254) | int(encrypted_bin[bit_index])
                bit_index += 1
            frame = flat.reshape(frame.shape)

        out.write(frame)

    cap.release()
    out.release()

def extract_message(video_path, key):
    if not os.path.exists(video_path):
        raise FileNotFoundError(f"Video not found: {video_path}")
    if not key:
        raise ValueError("Key cannot be empty.")

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Cannot open video file.")

    binary_data = ""
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        flat = frame.flatten()
        binary_data += ''.join(str(val & 1) for val in flat)

    cap.release()

    key_bin = to_binary(key)
    decrypted_bin = xor_encrypt(binary_data, key_bin)

    delimiter = '1111111111111110'
    end_idx = decrypted_bin.find(delimiter)
    if end_idx == -1:
        raise ValueError("No valid message found or incorrect key.")

    message_bin = decrypted_bin[:end_idx]
    return ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))

# Tkinter GUI
class VideoSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Video Steganography")
        self.root.geometry("500x400")

        self.video_path = ""

        tk.Label(root, text="Secret Message:").pack()
        self.message_entry = tk.Text(root, height=4)
        self.message_entry.pack(pady=5)

        tk.Label(root, text="Key:").pack()
        self.key_entry = tk.Entry(root, show="*", width=40)
        self.key_entry.pack(pady=5)

        tk.Button(root, text="Select Video", command=self.select_video).pack(pady=5)
        tk.Button(root, text="Hide Message", command=self.hide_message_gui).pack(pady=5)
        tk.Button(root, text="Extract Message", command=self.extract_message_gui).pack(pady=5)

        self.status_label = tk.Label(root, text="", fg="green")
        self.status_label.pack(pady=10)

    def select_video(self):
        path = filedialog.askopenfilename(filetypes=[("Video files", "*.avi *.mp4")])
        if path:
            self.video_path = path
            self.status_label.config(text=f"Selected: {os.path.basename(path)}")

    def hide_message_gui(self):
        if not self.video_path:
            messagebox.showerror("Error", "Please select a video first.")
            return

        message = self.message_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        if not message or not key:
            messagebox.showerror("Error", "Message and Key cannot be empty.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".avi", filetypes=[("AVI Video", "*.avi")])
        if not output_path:
            return

        try:
            hide_message(self.video_path, message, key, output_path)
            messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_message_gui(self):
        if not self.video_path:
            messagebox.showerror("Error", "Please select a video first.")
            return

        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Key cannot be empty.")
            return

        try:
            message = extract_message(self.video_path, key)
            messagebox.showinfo("Extracted Message", message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Main
if __name__ == "__main__":
    root = tk.Tk()
    app = VideoSteganographyApp(root)
    root.mainloop()
