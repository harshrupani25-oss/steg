import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk
import numpy as np
import wave
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from pydub import AudioSegment
from playsound import playsound
import tempfile

# Utility Functions
def to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def xor_encrypt(binary_text, key_binary):
    return ''.join(str(int(b) ^ int(key_binary[i % len(key_binary)])) for i, b in enumerate(binary_text))

def hide_message(audio_path, secret_message, key, output_path):
    if not os.path.exists(audio_path):
        raise FileNotFoundError(f"Audio not found: {audio_path}")
    if not key:
        raise ValueError("Key cannot be empty.")

    with wave.open(audio_path, 'rb') as audio:
        params = audio.getparams()
        frames = bytearray(list(audio.readframes(audio.getnframes())))

    message_bin = to_binary(secret_message) + '1111111111111110'
    key_bin = to_binary(key)
    encrypted_bin = xor_encrypt(message_bin, key_bin)

    if len(encrypted_bin) > len(frames):
        raise ValueError("Message is too large to hide in the audio.")

    for i in range(len(encrypted_bin)):
        frames[i] = (frames[i] & 0b11111110) | int(encrypted_bin[i])

    with wave.open(output_path, 'wb') as stego_audio:
        stego_audio.setparams(params)
        stego_audio.writeframes(bytes(frames))

def extract_message(audio_path, key):
    if not os.path.exists(audio_path):
        raise FileNotFoundError(f"Audio not found: {audio_path}")
    if not key:
        raise ValueError("Key cannot be empty.")

    with wave.open(audio_path, 'rb') as audio:
        frames = bytearray(list(audio.readframes(audio.getnframes())))

    binary_data = ''.join(str(frame & 1) for frame in frames)
    key_bin = to_binary(key)
    decrypted_bin = xor_encrypt(binary_data, key_bin)

    delimiter = '1111111111111110'
    end_idx = decrypted_bin.find(delimiter)
    if end_idx == -1:
        raise ValueError("No valid message found or incorrect key.")

    message_bin = decrypted_bin[:end_idx]
    return ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))

# Tkinter GUI
class AudioSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Audio Steganography")
        self.root.geometry("700x700")

        # Scrollable frame
        main_frame = tk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=1)

        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.audio_path = ""
        self.encoded_audio_path = ""

        # Secret message input
        tk.Label(self.scrollable_frame, text="Secret Message:").pack()
        self.message_entry = tk.Text(self.scrollable_frame, height=4, width=50)
        self.message_entry.pack(pady=5)

        # Key input with eye toggle
        tk.Label(self.scrollable_frame, text="Key:").pack()
        key_frame = tk.Frame(self.scrollable_frame)
        key_frame.pack(pady=5)
        self.key_entry = tk.Entry(key_frame, show="*", width=40)
        self.key_entry.pack(side=tk.LEFT)
        self.show_key = False
        tk.Button(key_frame, text="👁", command=self.toggle_password).pack(side=tk.LEFT, padx=5)

        # Buttons
        tk.Button(self.scrollable_frame, text="Select Audio", command=self.select_audio).pack(pady=5)
        tk.Button(self.scrollable_frame, text="Hide Message", command=self.hide_message_gui).pack(pady=5)
        tk.Button(self.scrollable_frame, text="Extract Message", command=self.extract_message_gui).pack(pady=5)

        # Play Original Button
        play_frame = tk.Frame(self.scrollable_frame)
        play_frame.pack(pady=5)
        tk.Button(play_frame, text="▶ Play Original (5s Preview)", command=self.play_original_preview).pack(side=tk.LEFT, padx=5)

        # Extracted text output
        tk.Label(self.scrollable_frame, text="Extracted Message:").pack()
        self.output_text = tk.Text(self.scrollable_frame, height=4, width=50)
        self.output_text.pack(pady=5)
        tk.Button(self.scrollable_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=5)

        # Waveform display
        self.fig, self.axs = plt.subplots(2, 1, figsize=(6, 4))
        self.fig.tight_layout(pad=3.0)
        self.canvas_fig = FigureCanvasTkAgg(self.fig, master=self.scrollable_frame)
        self.canvas_fig.get_tk_widget().pack(pady=10)

        # Clear button
        tk.Button(self.scrollable_frame, text="Clear All", command=self.clear_all).pack(pady=5)

    def toggle_password(self):
        if self.show_key:
            self.key_entry.config(show="*")
        else:
            self.key_entry.config(show="")
        self.show_key = not self.show_key

    def select_audio(self):
        path = filedialog.askopenfilename(filetypes=[("WAV audio", "*.wav")])
        if path:
            self.audio_path = path
            self.plot_waveform(path, 0, "Original Audio Waveform")

    def play_original_preview(self):
        if not self.audio_path:
            messagebox.showerror("Error", "Please select an audio file first.")
            return
        try:
            audio = AudioSegment.from_wav(self.audio_path)
            preview = audio[:5000]  # 5 seconds
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
            preview.export(temp_file.name, format="wav")
            temp_file.close()
            playsound(temp_file.name)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def hide_message_gui(self):
        if not self.audio_path:
            messagebox.showerror("Error", "Please select an audio file first.")
            return

        message = self.message_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        if not message or not key:
            messagebox.showerror("Error", "Message and Key cannot be empty.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV audio", "*.wav")])
        if not output_path:
            return

        try:
            hide_message(self.audio_path, message, key, output_path)
            self.encoded_audio_path = output_path
            self.plot_waveform(output_path, 1, "Encoded Audio Waveform")
            messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_message_gui(self):
        if not self.audio_path:
            messagebox.showerror("Error", "Please select an audio file first.")
            return

        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Key cannot be empty.")
            return

        try:
            message = extract_message(self.audio_path, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_to_clipboard(self):
        extracted = self.output_text.get("1.0", tk.END).strip()
        if extracted:
            self.root.clipboard_clear()
            self.root.clipboard_append(extracted)
            messagebox.showinfo("Copied", "Message copied to clipboard.")
        else:
            messagebox.showwarning("Empty", "No text to copy.")

    def plot_waveform(self, path, index, title):
        with wave.open(path, 'rb') as audio:
            frames = audio.readframes(audio.getnframes())
            samples = np.frombuffer(frames, dtype=np.int16)

        self.axs[index].clear()
        self.axs[index].plot(samples, linewidth=0.5)
        self.axs[index].set_title(title)
        self.canvas_fig.draw()

    def clear_all(self):
        self.message_entry.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.output_text.delete("1.0", tk.END)
        self.audio_path = ""
        self.encoded_audio_path = ""
        for ax in self.axs:
            ax.clear()
        self.canvas_fig.draw()

# Main entry
if __name__ == "__main__":
    root = tk.Tk()
    app = AudioSteganographyApp(root)
    root.mainloop()



