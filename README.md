# NVIDIA Vulnerability Scanner for Local Machine

## Description: 

Script in PowerShell to detect vulnerable versions of NVIDIA Graphics Driver and GeForce Experience in a Windows Local Machine. 

CVEs: CVE‑2019‑5687 and previous.

### Considerations: 

- Run the script with the Unrestricted or Bypass execution policies.


## Usage: 

PS E:\Pruebas C# PowerShell> .\DetectNVIDIAVulnLocal.ps1

or

PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectNVIDIAVulnLocal.ps1'

or (Recommended: Save the following command and execute it whenever you want. You do not need to download the script. You will always run the most updated version of the script)

PS C:\prueba> iex(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/v3nt4n1t0/DetectNVIDIAVulnLocal/master/DetectNVIDIAVulnLocal.ps1")


You can try differents methods.


