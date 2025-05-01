**Secureft: Secure File Transfer Tool (C++ AES-256-GCM)**

A simple command‑line utility to encrypt and decrypt files using AES-256 in GCM mode.

**Overview:**
- Encrypt any file with authenticated encryption (AES-256-GCM)
- Decrypt encrypted files, verifying integrity before restoring plaintext

**Features:**
- AES-256-GCM: Modern, widely adopted authenticated cipher
- Single binary: Encrypt or decrypt via a unified CLI

**Prerequisties:**
Compiler: C++17 or later
Libraries: OpenSSL

**Installation & Build**
1. Clone the repository:
```
git clone https://github.com/tfhammond/secure-file-transfer-cpp.git
cd secure-file-transfer-cpp
```
2. Make build directory
```
mkdir build
cd build
```
3. Configure with CMake
```
cmake ..
```
4. Compile (with Debug)
```
cmake --build . --config Debug
```

**Usage:**
Command Syntax
```
.\build\Debug\secureft.exe <mode> <input-file> <output-file> <key-file>
```
`<mode>`
- `encrypt` - Encrypts the input file into an authenticated ciphertext
- `decrypt` - Verifies and decrypts a ciphertext file back to plaintext

`<input-file>`
- For `encrypt`: the original file (ex: .txt)
- For `decrypt`: a previously encrypted file (.bin)

`<output-file>`
- For `encrypt`: where the ciphertext + 16-byte tag will be written
- For `decrypt`: where the recovered plaintext will be written

`<key-file>`
- For `encrypt`: a new file to store 32-byte key + 12-byte IV
- For `decrypt`: the existing key file created during encryption

**Examples**

**Encrypting a txt file**
`.\build\Debug\secureft.exe encrypt report.txt report.bin report.key`
- Input: `report.txt`
- Output: `report.bin` (ciphertext + 16-byte GCM tag)
- Key file: `report.key` (32-byte key + 12-byte IV)

**Decrypting the txt file**
`.\build\Debug\secureft.exe decrypt report.bin report_decrypted.txt report.key`
- Input: `report.bin`
- Output: `report_decrypted.txt` (original file restored)
- Key file: `report.key`
