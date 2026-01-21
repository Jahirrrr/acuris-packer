# Acuris Packer 🛡️

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)

**A professional-grade executable packer designed to protect Python binaries.**

Acuris Packer wraps your existing `.exe` file into an encrypted, password-protected container. It features a custom **Dark Mode UI**, **AES-256 encryption**, and **anti-tamper mechanisms** to prevent unauthorized access and reverse engineering.

## ✨ Features
* **🕵️ Obfuscation**: Randomizes internal variable names in the loader script to confuse reverse engineers.
* **💾 Recovery System**: Generates a `.dat` recovery file to restore the original binary if the password is lost.
* **📦 Zero Dependencies for Users**: The final output is a single, standalone `.exe` file.

## 🚀 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Jahirrrr/acuris-packer.git
    cd acuris-packer
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## 🛠️ Usage

### 1. Packing (Protecting an App)
Place your target executable in the `src` folder (optional) and run:

```bash
python src/packer.py YourApp.exe
```

Follow the prompts to set a password. The protected file will be generated in the dist/ folder.

2. Unlocking (Recovering Original App)
If you need to retrieve the original binary from a recovery file:

```bash
python src/unlocker.py YourApp_recovery.dat
```

⚠️ Disclaimer
This tool is intended for legitimate intellectual property protection. The author is not responsible for any misuse of this software. While this packer significantly increases security against casual snooping, no software is 100% immune to determined professional reverse engineering.

📄 License
Distributed under the MIT License.


---

### 6. `LICENSE`
```text
MIT License

Copyright (c) 2026 Zahir Hadi Athallah

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.