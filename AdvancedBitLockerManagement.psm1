<#	
	.NOTES
	===========================================================================
	 Created on:   	8/8/2024
	 Created by:   	Kiefer Easton
	 Filename:     	AdvancedBitLockerManagement.psm1
	===========================================================================
	.DESCRIPTION
		PowerShell module building upon the Microsoft BitLocker PowerShell
        module. Additional functionality includes detection functions to 
        confirm the presence of existing BitLocker key protectors within Active
        Directory as well as functions to purge non-escrowed recovery password
        key protectors. 
#>

function Add-LocalBitLockerRecoveryPassword {
    param (
        [string]$MountPoint = "C:"
    )
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $MountPoint
    try {
        $BitLockerVolume | Add-BitLockerKeyProtector -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        $Error[0]
    }
    return (Get-BitLockerVolume -MountPoint $MountPoint)
}

function Backup-LocalBitLockerRecoveryPasswordToAD {
    param (
        [string]$MountPoint = "C:"
    )
    $BitLockerPasswordRecoveryKeyCount = Get-LocalBitLockerRecoveryPasswordCount -MountPoint $MountPoint
    if ($BitLockerPasswordRecoveryKeyCount -eq 1) {
        $RecoveryPassword = Get-LocalBitLockerRecoveryPasswords -MountPoint $MountPoint
        try {
            Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $RecoveryPassword.KeyProtectorId
            return "BitLocker recovery password escrowed successfully to Active Directory."
        }
        catch {
            return $Error[0]
        }
    }
    else {
        return "Incorrect BitLocker Recovery Password count: $BitLockerPasswordRecoveryKeyCount"
    }
}

function Find-ADEscrowedBitLockerRecoveryPassword {
    param (
        [string]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory = $true)]
        [string]$LocalBitLockerKeyProtectorId
    )
    $ADBitLockerRecoveryInformation = Get-ADBitLockerRecoveryInformation -ComputerName $ComputerName
    foreach ($ADBitLockerKeyProtector in $ADBitLockerRecoveryInformation) {
        if ($ADBitLockerKeyProtector.KeyProtectorId -eq $LocalBitLockerKeyProtectorId) {
            return $true
        }
    }
    return $false
}

function Get-ADBitLockerRecoveryInformation {
    param (
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$SpecifyKeyProtectorId = "",
        [switch]$Latest
    )

    $ADBitLockerRecoveryInformation = @()

    $ADComputer = Get-ADComputer -Identity $ComputerName
    $ADComputerDN = $ADComputer.DistinguishedName
    $ADComputerRecoveryInformation = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $ADComputerDN -Properties *

    foreach ($ADComputerRecoveryInformationObject in $ADComputerRecoveryInformation) {

        $SplitName = $ADComputerRecoveryInformationObject.Name -split "({)"
        [string]$KeyProtectorId = $SplitName[1] + $SplitName[2]
        [string]$RecoveryPassword = $ADComputerRecoveryInformationObject.'msFVE-RecoveryPassword'
        [datetime]$KeyProtectorCreatedDate = $SplitName[0]
        # For whatever reason, the key protector created date is only stored within the 'name' field
        # and it does not properly account for DST, so we have to do that
        if (([System.TimeZoneInfo]::ConvertTimeFromUtc(($KeyProtectorCreatedDate).ToString(), [System.TimeZoneInfo]::FindSystemTimeZoneById((Get-TimeZone).Id))).isdaylightsavingtime()) {
            $KeyProtectorCreatedDate = $KeyProtectorCreatedDate.AddHours(-1)
        }
        [datetime]$KeyProtectorEscrowedDate = $ADComputerRecoveryInformationObject.whenCreated

        $ADBitLockerObject = New-Object -TypeName PSObject
        $ADBitLockerObject | Add-Member -Name 'KeyProtectorId' -MemberType Noteproperty -Value $KeyProtectorId
        $ADBitLockerObject | Add-Member -Name 'RecoveryPassword' -MemberType Noteproperty -Value $RecoveryPassword
        $ADBitLockerObject | Add-Member -Name 'KeyProtectorCreatedDate' -MemberType Noteproperty -Value $KeyProtectorCreatedDate
        $ADBitLockerObject | Add-Member -Name 'KeyProtectorEscrowedDate' -MemberType Noteproperty -Value $KeyProtectorEscrowedDate

        $ADBitLockerRecoveryInformation += $ADBitLockerObject
    }
    if ($Latest) {
        return ($ADBitLockerRecoveryInformation | Sort-Object -Property 'Key Protector Escrowed Date' | Select-Object -Last 1)
    }
    if ($SpecifyKeyProtectorId -ne "") {
        return ($ADBitLockerRecoveryInformation | Where-Object { $_.KeyProtectorId -eq $SpecifyKeyProtectorId })
    }
    else {
        return $ADBitLockerRecoveryInformation
    }
}

function Get-LocalBitLockerRecoveryInformation {
    param (
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$MountPoint = "C:"
    )
    $LocalBitLockerRecoveryPasswords = Get-LocalBitLockerRecoveryPasswords -MountPoint $MountPoint
    foreach ($LocalBitLockerRecoveryPassword in $LocalBitLockerRecoveryPasswords) {
        $EscrowStatus = Find-ADEscrowedBitLockerRecoveryPassword -ComputerName $ComputerName -LocalBitLockerKeyProtectorId $LocalBitLockerRecoveryPassword.KeyProtectorId
        $LocalBitLockerRecoveryPassword | Add-Member -Name 'EscrowStatus' -MemberType NoteProperty -Value $EscrowStatus
        [nullable[datetime]]$KeyProtectorCreatedDate = $null
        [nullable[datetime]]$KeyProtectorEscrowedDate = $null
        if ($EscrowStatus -eq $true) {
            $ADBitLockerRecoveryInformation = Get-ADBitLockerRecoveryInformation -ComputerName $ComputerName -SpecifyKeyProtectorId $LocalBitLockerRecoveryPassword.KeyProtectorId
            $KeyProtectorCreatedDate = $ADBitLockerRecoveryInformation.KeyProtectorCreatedDate
            $KeyProtectorEscrowedDate = $ADBitLockerRecoveryInformation.KeyProtectorEscrowedDate
        }
        $LocalBitLockerRecoveryPassword | Add-Member -Name 'KeyProtectorCreatedDate' -MemberType Noteproperty -Value $KeyProtectorCreatedDate
        $LocalBitLockerRecoveryPassword | Add-Member -Name 'KeyProtectorEscrowedDate' -MemberType Noteproperty -Value $KeyProtectorEscrowedDate
    }
    return $LocalBitLockerRecoveryPasswords
}

function Get-LocalBitLockerRecoveryPasswordCount {
    param (
        [string]$MountPoint = "C:"
    )
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $MountPoint
    $BitLockerRecoveryPasswordCount = ($BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).Count
    
    return $BitLockerRecoveryPasswordCount
}

function Get-LocalBitLockerRecoveryPasswords {
    param (
        [string]$MountPoint = "C:"
    )
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $MountPoint
    $KeyProtectors = $BitLockerVolume.KeyProtector
    $RecoveryPasswords = @()
    foreach ($KeyProtector in $KeyProtectors) {
        if ($KeyProtector.KeyProtectorType -eq "RecoveryPassword") {
            $RecoveryPasswords += $KeyProtector
        }
    }
    return $RecoveryPasswords
}

function Remove-LocalBitLockerRecoveryPasswords {
    param (
        [string]$MountPoint = "C:"
    )
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $MountPoint
    $KeyProtectors = $BitLockerVolume.KeyProtector
    foreach ($KeyProtector in $KeyProtectors) {
        if ($KeyProtector.KeyProtectorType -eq "RecoveryPassword") {
            try {
                $BitLockerVolume | Remove-BitLockerKeyProtector -KeyProtectorId $KeyProtector.KeyProtectorId -WarningAction SilentlyContinue | Out-Null
            }
            catch {
                $Error[0]
            }
        }
    }
    return (Get-BitLockerVolume -MountPoint $MountPoint)
}