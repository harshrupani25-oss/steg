import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image
import numpy as np
import wave
import cv2
import os

# ====== Common Helpers ======
DELIMITER = '1111111111111110'  # 16x '1' + '0' to mark end

def to_binary(text: str) -> str:
    return ''.join(format(ord(c), '08b') for c in text)

def xor_encrypt(binary_text: str, key_binary: str) -> str:
    if not key_binary:
        raise ValueError("Key cannot be empty.")
    return ''.join(str(int(b) ^ int(key_binary[i % len(key_binary)])) for i, b in enumerate(binary_text))

def ensure_non_empty_paths(path: str, key: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    if not key:
        raise ValueError("Key cannot be empty.")

def ensure_message_not_empty(msg: str, key: str):
    if not msg:
        raise ValueError("Message cannot be empty.")
    if not key:
        raise ValueError("Key cannot be empty.")

# ====== IMAGE Steganography ======
def image_hide_message(image_path: str, secret_message: str, key: str, output_path: str):
    ensure_non_empty_paths(image_path, key)
    ensure_message_not_empty(secret_message, key)

    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img, dtype=np.uint8)

    message_bin = to_binary(secret_message) + DELIMITER
    key_bin = to_binary(key)
    encrypted_bin = xor_encrypt(message_bin, key_bin)

    capacity_bits = pixels.size  # each channel LSB used
    if len(encrypted_bin) > capacity_bits:
        raise ValueError(f"Message too large for this image. Capacity: {capacity_bits} bits, needed: {len(encrypted_bin)} bits.")

    flat = pixels.flatten()
    for i in range(len(encrypted_bin)):
        flat[i] = (flat[i] & 0b11111110) | int(encrypted_bin[i])

    new_pixels = flat.reshape(pixels.shape)
    Image.fromarray(new_pixels).save(output_path)

def image_extract_message(image_path: str, key: str) -> str:
    ensure_non_empty_paths(image_path, key)

    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img, dtype=np.uint8).flatten()

    binary_data = ''.join(str(px & 1) for px in pixels)

    key_bin = to_binary(key)
    decrypted_bin = xor_encrypt(binary_data, key_bin)

    end_idx = decrypted_bin.find(DELIMITER)
    if end_idx == -1:
        raise ValueError("No valid message found (wrong key or wrong file).")
    message_bin = decrypted_bin[:end_idx]
    return ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))

# ====== AUDIO (WAV) Steganography ======
def audio_hide_message(audio_path: str, secret_message: str, key: str, output_path: str):
    ensure_non_empty_paths(audio_path, key)
    ensure_message_not_empty(secret_message, key)

    song = wave.open(audio_path, mode='rb')
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    message_bin = to_binary(secret_message) + DELIMITER
    key_bin = to_binary(key)
    encrypted_bin = xor_encrypt(message_bin, key_bin)

    if len(encrypted_bin) > len(frame_bytes):
        song.close()
        raise ValueError(f"Message too large for this audio. Capacity: {len(frame_bytes)} bits, needed: {len(encrypted_bin)} bits.")

    for i in range(len(encrypted_bin)):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(encrypted_bin[i])

    modified = wave.open(output_path, 'wb')
    modified.setparams(song.getparams())
    modified.writeframes(bytes(frame_bytes))
    song.close()
    modified.close()

def audio_extract_message(audio_path: str, key: str) -> str:
    ensure_non_empty_paths(audio_path, key)

    song = wave.open(audio_path, mode='rb')
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))
    song.close()

    bits = ''.join(str(b & 1) for b in frame_bytes)
    key_bin = to_binary(key)
    decrypted_bin = xor_encrypt(bits, key_bin)

    end_idx = decrypted_bin.find(DELIMITER)
    if end_idx == -1:
        raise ValueError("No valid message found (wrong key or wrong file).")
    message_bin = decrypted_bin[:end_idx]
    return ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))

# ====== VIDEO Steganography (frames only; audio not preserved) ======
def video_hide_message(video_path: str, secret_message: str, key: str, output_path: str):
    ensure_non_empty_paths(video_path, key)
    ensure_message_not_empty(secret_message, key)

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Cannot open video file.")

    fps     = cap.get(cv2.CAP_PROP_FPS) or 25.0
    width   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height  = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    frames  = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    chans   = 3  # BGR
    capacity_bits = width * height * chans * frames

    message_bin = to_binary(secret_message) + DELIMITER
    key_bin     = to_binary(key)
    encrypted   = xor_encrypt(message_bin, key_bin)

    if len(encrypted) > capacity_bits:
        cap.release()
        raise ValueError(f"Message too large for this video. Capacity: {capacity_bits} bits, needed: {len(encrypted)} bits.")

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
    if not out.isOpened():
        # fallback to MJPG if needed
        fourcc = cv2.VideoWriter_fourcc(*'MJPG')
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        if not out.isOpened():
            cap.release()
            raise ValueError("Failed to open VideoWriter. Try a different output path/codec.")

    bit_idx = 0
    total_bits = len(encrypted)

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        if bit_idx < total_bits:
            flat = frame.flatten()
            for i in range(len(flat)):
                if bit_idx >= total_bits:
                    break
                flat[i] = (flat[i] & 254) | int(encrypted[bit_idx])
                bit_idx += 1
            frame = flat.reshape(frame.shape)
        out.write(frame)

    cap.release()
    out.release()

def video_extract_message(video_path: str, key: str) -> str:
    ensure_non_empty_paths(video_path, key)

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Cannot open video file.")

    bits = []
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        flat = frame.flatten()
        bits.extend(str(v & 1) for v in flat)
    cap.release()

    binary_data = ''.join(bits)
    key_bin = to_binary(key)
    decrypted = xor_encrypt(binary_data, key_bin)

    end_idx = decrypted.find(DELIMITER)
    if end_idx == -1:
        raise ValueError("No valid message found (wrong key or wrong file).")
    message_bin = decrypted[:end_idx]
    return ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))

# ====== GUI ======
class StegApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Suite (Image + Audio + Video)")
        self.root.geometry("620x520")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.image_tab = ttk.Frame(notebook)
        self.audio_tab = ttk.Frame(notebook)
        self.video_tab = ttk.Frame(notebook)

        notebook.add(self.image_tab, text="Image")
        notebook.add(self.audio_tab, text="Audio (WAV)")
        notebook.add(self.video_tab, text="Video")

        self.build_image_tab()
        self.build_audio_tab()
        self.build_video_tab()

    # ---------- Image Tab ----------
    def build_image_tab(self):
        self.img_path = ""
        frm = self.image_tab

        ttk.Button(frm, text="Select Image (PNG/BMP)", command=self.select_image).pack(pady=6)

        ttk.Label(frm, text="Secret Message:").pack()
        self.img_msg = tk.Text(frm, height=5, width=70)
        self.img_msg.pack(pady=4)

        ttk.Label(frm, text="Key:").pack()
        self.img_key = ttk.Entry(frm, show="*")
        self.img_key.pack(pady=4, fill="x", padx=20)

        btns = ttk.Frame(frm)
        btns.pack(pady=8)
        ttk.Button(btns, text="Hide Message", command=self.image_hide).pack(side="left", padx=6)
        ttk.Button(btns, text="Extract Message", command=self.image_extract).pack(side="left", padx=6)

        self.img_status = ttk.Label(frm, text="", foreground="green")
        self.img_status.pack(pady=6)

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if path:
            self.img_path = path
            self.img_status.config(text=f"Selected: {os.path.basename(path)}")

    def image_hide(self):
        if not self.img_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        message = self.img_msg.get("1.0", tk.END).strip()
        key = self.img_key.get().strip()
        output = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not output:
            return
        try:
            image_hide_message(self.img_path, message, key, output)
            messagebox.showinfo("Success", f"Hidden in: {output}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def image_extract(self):
        if not self.img_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        key = self.img_key.get().strip()
        try:
            msg = image_extract_message(self.img_path, key)
            messagebox.showinfo("Extracted Message", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------- Audio Tab ----------
    def build_audio_tab(self):
        self.aud_path = ""
        frm = self.audio_tab

        ttk.Button(frm, text="Select Audio (WAV)", command=self.select_audio).pack(pady=6)

        ttk.Label(frm, text="Secret Message:").pack()
        self.aud_msg = tk.Text(frm, height=5, width=70)
        self.aud_msg.pack(pady=4)

        ttk.Label(frm, text="Key:").pack()
        self.aud_key = ttk.Entry(frm, show="*")
        self.aud_key.pack(pady=4, fill="x", padx=20)

        btns = ttk.Frame(frm)
        btns.pack(pady=8)
        ttk.Button(btns, text="Hide Message", command=self.audio_hide).pack(side="left", padx=6)
        ttk.Button(btns, text="Extract Message", command=self.audio_extract).pack(side="left", padx=6)

        self.aud_status = ttk.Label(frm, text="", foreground="green")
        self.aud_status.pack(pady=6)

    def select_audio(self):
        path = filedialog.askopenfilename(filetypes=[("WAV Audio", "*.wav")])
        if path:
            self.aud_path = path
            self.aud_status.config(text=f"Selected: {os.path.basename(path)}")

    def audio_hide(self):
        if not self.aud_path:
            messagebox.showerror("Error", "Please select a WAV file.")
            return
        message = self.aud_msg.get("1.0", tk.END).strip()
        key = self.aud_key.get().strip()
        output = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV Audio", "*.wav")])
        if not output:
            return
        try:
            audio_hide_message(self.aud_path, message, key, output)
            messagebox.showinfo("Success", f"Hidden in: {output}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def audio_extract(self):
        if not self.aud_path:
            messagebox.showerror("Error", "Please select a WAV file.")
            return
        key = self.aud_key.get().strip()
        try:
            msg = audio_extract_message(self.aud_path, key)
            messagebox.showinfo("Extracted Message", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------- Video Tab ----------
    def build_video_tab(self):
        self.vid_path = ""
        frm = self.video_tab

        ttk.Button(frm, text="Select Video (AVI/MP4)", command=self.select_video).pack(pady=6)

        ttk.Label(frm, text="Secret Message:").pack()
        self.vid_msg = tk.Text(frm, height=5, width=70)
        self.vid_msg.pack(pady=4)

        ttk.Label(frm, text="Key:").pack()
        self.vid_key = ttk.Entry(frm, show="*")
        self.vid_key.pack(pady=4, fill="x", padx=20)

        btns = ttk.Frame(frm)
        btns.pack(pady=8)
        ttk.Button(btns, text="Hide Message", command=self.video_hide).pack(side="left", padx=6)
        ttk.Button(btns, text="Extract Message", command=self.video_extract).pack(side="left", padx=6)

        self.vid_status = ttk.Label(frm, text="Note: Output AVI will not preserve original audio.", foreground="blue")
        self.vid_status.pack(pady=6)

    def select_video(self):
        path = filedialog.askopenfilename(filetypes=[("Video files", "*.avi *.mp4")])
        if path:
            self.vid_path = path
            self.vid_status.config(text=f"Selected: {os.path.basename(path)} (Audio not preserved in output)", foreground="blue")

    def video_hide(self):
        if not self.vid_path:
            messagebox.showerror("Error", "Please select a video.")
            return
        message = self.vid_msg.get("1.0", tk.END).strip()
        key = self.vid_key.get().strip()
        output = filedialog.asksaveasfilename(defaultextension=".avi", filetypes=[("AVI Video", "*.avi")])
        if not output:
            return
        try:
            video_hide_message(self.vid_path, message, key, output)
            messagebox.showinfo("Success", f"Hidden in: {output}\n(Note: audio not preserved)")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def video_extract(self):
        if not self.vid_path:
            messagebox.showerror("Error", "Please select a video.")
            return
        key = self.vid_key.get().strip()
        try:
            msg = video_extract_message(self.vid_path, key)
            messagebox.showinfo("Extracted Message", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ====== Main ======
if __name__ == "__main__":
    root = tk.Tk()
    StegApp(root)
    root.mainloop()
