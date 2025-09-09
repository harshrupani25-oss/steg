# Steg – Steganography Tool

A Python-based **steganography tool** that allows you to **hide and extract secret messages/files** within **images, audio, and video**.  
The tool provides an intuitive workflow with **file loading, preview options, and smooth execution in VS Code**.

---

## ✨ Features
- 🔒 Hide and extract data in **images, audio, and video**
- 👀 **Preview** of selected media before processing
- ⚡ Smooth integration with **VS Code**
- 🛠 Built with **Python**, using **Pillow**, **NumPy**, and **OpenCV**

---

## 🛠 Tech Stack
- **Language:** Python 3.x  
- **Core Libraries:**  
  - [Pillow](https://pypi.org/project/Pillow/) – image processing  
  - [NumPy](https://pypi.org/project/numpy/) – array & matrix operations  
  - [OpenCV](https://pypi.org/project/opencv-python/) – video processing  
  - `wave` – audio support (comes with Python standard library)  

---

## 📦 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/harshrupani25-oss/steg.git
   cd steg


Create a virtual environment (recommended):
python -m venv venv
source venv/bin/activate   # on Linux/Mac
venv\Scripts\activate      # on Windows


Install dependencies directly from here:
pip install numpy>=1.24.0 Pillow>=10.0.0 opencv-python>=4.8.0


usage 
python steg.py


Requirements (inline)
numpy>=1.24.0
Pillow>=10.0.0
opencv-python>=4.8.0

👨‍💻 Author
Harsh Rupani