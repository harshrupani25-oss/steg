import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import os

# Utility Functions
def to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def xor_encrypt(binary_text, key_binary):
    return ''.join(str(int(b) ^ int(key_binary[i % len(key_binary)])) for i, b in enumerate(binary_text))

def hide_message(image_path, secret_message, key, output_path):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    if not key:
        raise ValueError("Key cannot be empty.")

    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img, dtype=np.uint8)

    message_bin = to_binary(secret_message) + '1111111111111110'
    key_bin = to_binary(key)
    encrypted_bin = xor_encrypt(message_bin, key_bin)

    if len(encrypted_bin) > pixels.size:
        raise ValueError("Message is too large to hide in the image.")

    flat_pixels = pixels.flatten()
    for i in range(len(encrypted_bin)):
        flat_pixels[i] = (flat_pixels[i] & 0b11111110) | int(encrypted_bin[i])

    new_pixels = flat_pixels.reshape(pixels.shape)
    Image.fromarray(new_pixels).save(output_path)

def extract_message(image_path, key):
    if not os.path.exists(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    if not key:
        raise ValueError("Key cannot be empty.")

    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten()

    binary_data = ''.join(str(pixel & 1) for pixel in flat_pixels)
    key_bin = to_binary(key)
    decrypted_bin = xor_encrypt(binary_data, key_bin)

    delimiter = '1111111111111110'
    end_idx = decrypted_bin.find(delimiter)
    if end_idx == -1:
        raise ValueError("No valid message found or incorrect key.")

    message_bin = decrypted_bin[:end_idx]
    return ''.join(chr(int(message_bin[i:i+8], 2)) for i in range(0, len(message_bin), 8))

# Tkinter GUI
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography with Preview")
        self.root.geometry("650x700")

        self.image_path = ""
        self.image_preview = None
        self.encoded_preview = None
        self.show_password = False

        # Scrollable Frame
        main_frame = tk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=1)

        canvas = tk.Canvas(main_frame)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        scrollbar = tk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        self.frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=self.frame, anchor="nw")

        # Widgets
        tk.Label(self.frame, text="Secret Message:").pack()
        self.message_entry = tk.Text(self.frame, height=4)
        self.message_entry.pack(pady=5)

        tk.Label(self.frame, text="Key:").pack()
        key_frame = tk.Frame(self.frame)
        key_frame.pack(pady=5)

        self.key_entry = tk.Entry(key_frame, show="*", width=35)
        self.key_entry.pack(side=tk.LEFT)

        self.toggle_btn = tk.Button(key_frame, text="👁", command=self.toggle_password)
        self.toggle_btn.pack(side=tk.LEFT, padx=5)

        tk.Button(self.frame, text="Select Image", command=self.select_image).pack(pady=5)
        self.preview_label_text = tk.Label(self.frame, text="No Image Selected")
        self.preview_label_text.pack()
        self.preview_label = tk.Label(self.frame)
        self.preview_label.pack(pady=5)

        tk.Button(self.frame, text="Hide Message", command=self.hide_message_gui).pack(pady=5)
        tk.Button(self.frame, text="Extract Message", command=self.extract_message_gui).pack(pady=5)
        tk.Button(self.frame, text="Copy Extracted Text", command=self.copy_text).pack(pady=5)
        tk.Button(self.frame, text="Clear All", command=self.clear_all).pack(pady=5)

        self.output_text = tk.Text(self.frame, height=5, width=50)
        self.output_text.pack(pady=10)

        tk.Label(self.frame, text="Encoded Image Preview:").pack()
        self.encoded_label = tk.Label(self.frame)
        self.encoded_label.pack(pady=5)

        self.status_label = tk.Label(self.frame, text="", fg="green")
        self.status_label.pack(pady=10)

    def toggle_password(self):
        if self.show_password:
            self.key_entry.config(show="*")
            self.show_password = False
        else:
            self.key_entry.config(show="")
            self.show_password = True

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if path:
            self.image_path = path
            img = Image.open(path)
            img.thumbnail((200, 200))
            self.image_preview = ImageTk.PhotoImage(img)
            self.preview_label.config(image=self.image_preview)
            self.preview_label.image = self.image_preview
            self.preview_label_text.config(text=f"Selected: {os.path.basename(path)}")

    def hide_message_gui(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first.")
            return

        message = self.message_entry.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        if not message or not key:
            messagebox.showerror("Error", "Message and Key cannot be empty.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not output_path:
            return

        try:
            hide_message(self.image_path, message, key, output_path)
            messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")

            # Show encoded image preview
            img = Image.open(output_path)
            img.thumbnail((200, 200))
            self.encoded_preview = ImageTk.PhotoImage(img)
            self.encoded_label.config(image=self.encoded_preview)
            self.encoded_label.image = self.encoded_preview

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_message_gui(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first.")
            return

        key = self.key_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Key cannot be empty.")
            return

        try:
            message = extract_message(self.image_path, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, message)
            messagebox.showinfo("Success", "Message extracted successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_text(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo("Copied", "Extracted text copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No text to copy.")

    def clear_all(self):
        self.message_entry.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.output_text.delete("1.0", tk.END)
        self.preview_label.config(image="")
        self.preview_label_text.config(text="No Image Selected")
        self.encoded_label.config(image="")
        self.image_path = ""
        self.status_label.config(text="")

# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
