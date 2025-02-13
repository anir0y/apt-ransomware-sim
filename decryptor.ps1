
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
