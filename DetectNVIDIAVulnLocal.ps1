#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Author: Roberto Berrio (@v3nt4n1t0)
# Website: https://github.com/v3nt4n1t0
#
#
# Description: Script in PowerShell to detect vulnerable versions of NVIDIA Graphics Driver and GeForce Experience in a Windows Local Machine. 
#
# CVEs: CVE‑2019‑5678 and previous.
# 
# 
# Considerations: 
#
# - Run the script with the Unrestricted or Bypass execution policies from Domain Controller
#
#
# Usage: 
#
# PS E:\Pruebas C# PowerShell> .\DetectNVIDIAVulnLocal.ps1
#
# PS C:\prueba> powershell.exe -ExecutionPolicy Bypass -File 'E:\Pruebas C# PowerShell\DetectNVIDIAVulnLocal.ps1'
# 
################################################################################################################################################## 


$machine = (Get-WmiObject -class win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').ipaddress[0] + "," +[Environment]::GetEnvironmentVariable("ComputerName")
$tipo=Get-WmiObject win32_VideoController -Property AdapterCompatibility
echo ""
if($tipo.AdapterCompatibility -like '*NVIDIA*') 
{
    $gpu=Get-WmiObject win32_VideoController -Property Caption
    $gpuversion=Get-WmiObject win32_VideoController -Property DriverVersion
    $version = $gpuversion.DriverVersion.Substring($gpuversion.DriverVersion.Length - 6, 6)
    
    if($gpu.Caption -like '*Geforce*') {
        if($version -lt 4.3064){Write-Host -ForegroundColor Red -NoNewline " $machine -> Vulnerable drivers! Update drivers to version 430.64 or higher"}
        else{Write-Host -NoNewline " $machine -> Non-vulnerable NVIDIA drivers"}
    }
    elseif(($gpu.Caption -like '*Quadro*') -or ($gpu.Caption -like '*NVS*')){
        if($version -lt 4.3064){Write-Host -ForegroundColor Red -NoNewline " $machine -> Vulnerable drivers! Update drivers to version 430.64 or higher"}
        else{Write-Host -NoNewline " $machine -> Non-vulnerable NVIDIA drivers"}
    }
    elseif($gpu.Caption -like '*Tesla*'){
        if($version -lt 4.2525){Write-Host -ForegroundColor Red -NoNewline " $machine -> Vulnerable drivers! Update drivers to version 425.25 or higher"}
        else{Write-Host -NoNewline " $machine -> Non-vulnerable NVIDIA drivers"}
    }

    ls HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {       
        if($_.GetValue("DisplayName") -like "NVIDIA GeForce Experience*"){
        $GFExperienceVersion = $_.GetValue("DisplayVersion")
        $SbStrversion = $GFExperienceVersion.Substring(0,4)
        }
    }

    ls HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object -Process {
        if($_.GetValue("DisplayName") -like "NVIDIA GeForce Experience*"){
        $GFExperienceVersion = $_.GetValue("DisplayVersion")
        $SbStrversion = $GFExperienceVersion.Substring(0,4)
        }
    }

    if(!$GFExperienceVersion){" | Does not have NVIDIA GeForce Experience installed`n" }
    elseif($SbStrversion -lt 3.19){Write-Host -NoNewline " | "; Write-Host -ForegroundColor Red "GeForce Experience is vulnerable! Update to version 3.18.0.94 or higher`n"}
    else{" | NVIDIA GeForce Experience is not vulnerable`n"}
}
else{ " $machine does not have NVIDIA GPU or does not contain NVIDIA drivers`n"}
