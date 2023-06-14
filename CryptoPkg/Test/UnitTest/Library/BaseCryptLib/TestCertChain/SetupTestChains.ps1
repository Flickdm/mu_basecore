#Requires -RunAsAdministrator
# This script *unfortunately* requires ADMIN privileges due to New-SelfSignedCertificate

# Load the helper functions
. ./CertificateAndSignerHelpers.ps1

# This script relies on this script to format and sign Authenticated
$FormatAuthVar = "./FormatAuthenticatedVariable.py"

# Have to leave this outside the globals - since it's inaccessible during initialization of the hashtable
$Password = "password"
$DataFolder = "./Test"
$TestDataName = "TestData"
$CertName = "Certs"

# Global Variables used throughout the script
$Globals = @{
    Certificate = @{
        Store = "Cert:\LocalMachine\My\"
        Organization = "contoso"
        Password = $Password
        SecurePassword = ConvertTo-SecureString $Password -Force -AsPlainText
        LifeYears = 10 # How long in the future should the Certificate be valid
    }
    Variable = @{
        Attributes = "NV,BS,RT,AT"
        Guid = "b3f4fb27-f382-4484-9b77-226b2b4348bb"
    }
    Layout = @{
        DataFolder = $DataFolder
        CertName = $CertName 
        CertificateFolder = "$DataFolder/$CertName"
        TestDataName = $TestDataName
        TestDataFolder = "$DataFolder/$TestDataName"
    }
}

# Clean up from a pervious run
Remove-Item $Globals.Layout.DataFolder -Recurse -Force -Confirm:$false
New-Item -Path $Globals.Layout.DataFolder -ItemType Directory
New-Item -Path $Globals.Layout.CertificateFolder -ItemType Directory
New-Item -Path $Globals.Layout.TestDataFolder -ItemType Directory

# =======================================================================================
# Test Name: Additional Certificates
# Test Description:
#   This test checks to see if variables signed by a single certificate and has
#   additional certificates added to the certificate chain still works. This will
#   increase the signature size as it add's additional certificates looking for a
#   breaking point
#
#   Signers: 1 (End Entity)
#   Added Certificates: 1..3 (Intermediate Certificate)
#
#   Expectation: All the signed variables should work, further the Openssl code
#       will check the certificate chain to ensure the chain is valid
#
# =============================================================================
# 2k Keys
# =============================================================================
$VariableName = "MockVar"
# Verify 2k, 3k, 4k keylength certificate support
$CommonName = "Additional Certificates"
$TestGroup = "AdditionalCertificates"

# =============================================================================
# MockVar Trust Anchor
# =============================================================================
# Trust anchor should be able to be any size
$KeyLength = 4096 
# Variable Prefix must be different
$VariablePrefix = "m${KeyLength}TrustAnchor"

# Self signed
$TrustAnchorParams = GetRootCertificateParams $KeyLength $CommonName "Trust Anchor"
$TrustAnchor = GenerateCertificate $TrustAnchorParams $VariableName $VariablePrefix

# Variable Prefix must be different
$VariablePrefix = "m${KeyLength}Intermediate0"

# Issued by Trust Anchor
$IntermediateParams = GetIntermediateCertificateParams $KeyLength $CommonName "Intermediate0" $TrustAnchor.Cert
$Intermediate0 = GenerateCertificate $IntermediateParams $VariableName $VariablePrefix

# Issued by Intermediate0
$VariablePrefix = "m${KeyLength}Intermediate1"
$IntermediateParams = GetIntermediateCertificateParams $KeyLength $CommonName "Intermediate1" $Intermediate0.Cert
$Intermediate1 = GenerateCertificate $IntermediateParams $VariableName $VariablePrefix

# Issued by Intermediate1
$VariablePrefix = "m${KeyLength}Intermediate2"
$IntermediateParams = GetIntermediateCertificateParams $KeyLength $CommonName "Intermediate2" $Intermediate1.Cert
$Intermediate2 = GenerateCertificate $IntermediateParams $VariableName $VariablePrefix

# =============================================================================
#  Generates signature signed by one 2k end entity certificate
# 1 Additional Certficiate(s)
# =============================================================================
$KeyLength = 2048
# Variable data *should* be different
$VariableData =  "Test: ${TestGroup} - Description: Signed By ${KeyLength} certificate and includes 1 additional certificate(s)"
# Variable Prefix must be different
$VariablePrefix = "m1${TestGroup}"

$EndEntityParams = GetEndEntityCertificateParams $KeyLength $CommonName "Signer" $Intermediate0.Cert
$2KMockVar = GenerateCertificate $EndEntityParams $VariableName $VariablePrefix
$ret = GenerateTestData $VariableName $VariablePrefix $VariableData @($2KMockVar.CertInfo) $null @($Intermediate0.CertPath)
if (!$ret) {
    Exit
}

# =============================================================================
# Generates signature signed by one 3k end entity certificate
# 2 Additional Certficiate(s)
# =============================================================================
$KeyLength = 3072
# Variable data *should* be different
$VariableData =  "Test: ${TestGroup} - Description: Signed By ${KeyLength} certificate and includes 2 additional certificate(s)"
# Variable Prefix must be different - as this will appended to the front of the C Variable to keep them distinct
$VariablePrefix = "m2${TestGroup}"

$EndEntityParams = GetEndEntityCertificateParams $KeyLength $CommonName "Signer" $Intermediate1.Cert
$3KMockVar = GenerateCertificate $EndEntityParams $VariableName $VariablePrefix
$ret = GenerateTestData $VariableName $VariablePrefix $VariableData @($3KMockVar.CertInfo) $null `
     @($Intermediate1.CertPath, $Intermediate0.CertPath)
if (!$ret) {
    Exit
}

# =============================================================================
#  Generates signature signed by one 4k end entity certificate
# 3 Additional Certficiate(s)
# =============================================================================
$KeyLength = 4096
# Variable data *should* be different
$VariableData =  "Test: ${TestGroup} - Description: Signed By ${KeyLength} certificate and includes 3 additional certificate(s)"
# Variable Prefix must be different - as this will appended to the front of the C Variable to keep them distinct
$VariablePrefix = "m3${TestGroup}"

$EndEntityParams = GetEndEntityCertificateParams $KeyLength $CommonName "Signer" $Intermediate2.Cert
$4KMockVar = GenerateCertificate $EndEntityParams $VariableName $VariablePrefix
$ret = GenerateTestData $VariableName $VariablePrefix $VariableData @($4KMockVar.CertInfo) $null `
    @($Intermediate2.CertPath, $Intermediate1.CertPath, $Intermediate0.CertPath)
if (!$ret) {
    Exit
}

# =============================================================================
# delete the certs from the keystore
# =============================================================================

# Locate by organization and delete
$Organization = $Globals.Certificate.Organization
$items = Get-ChildItem -Path $Globals.Certificate.Store -Recurse
foreach ($item in $items) {
     if($item.Subject -like "*$Organization*") {
         $item | Remove-Item -Force
     }
}

# Remove-Item $Globals.Layout.CertificateFolder -Recurse -Force -Confirm:$false
# Remove-Item $Globals.Layout.TestDataFolder -Recurse -Force -Confirm:$false

# =============================================================================
# Copy All the C arrays and variables to a single header and source file
# =============================================================================

$OutFile = Join-Path -Path $Globals.Layout.DataFolder -ChildPath "Exported.c"

#Include Headers
$SourceContents = @()
$SourceContents += "#include `"AuthData.h`"`n#include <Uefi.h>`n`n"

Get-ChildItem $Globals.Layout.DataFolder -Filter '*signature.c' -Recurse `
 | Where {!($_.Name -like '*Empty*')} `
 | sort creationtime `
 | Where {$_.Name.substring($_.Name.length -3, 3)  -Match 'c'} `
 | Foreach-Object {
    $SourceContents += cat $_.FullName
}

$SourceContents | Out-File -Encoding Ascii -FilePath $OutFile

$OutFile = Join-Path -Path $Globals.Layout.DataFolder -ChildPath "Exported.h"
$HeaderContents = @()

# include guard
$HeaderContents += "#ifndef AUTH_DATA_H_`n#define AUTH_DATA_H_`n`n"
$HeaderContents += "#include <Uefi/UefiBaseType.h>`n`n"

Get-ChildItem $Globals.Layout.DataFolder -Filter '*signature.h' -Recurse `
 | Where {!($_.Name -like '*Empty*')} `
 | sort creationtime `
 | Where {$_.Name.substring($_.Name.length -3, 3)  -Match 'h'} `
 | Foreach-Object {
    $HeaderContents += cat $_.FullName
}

#include end guard
$HeaderContents += "#endif AUTH_DATA_H_`n"

$HeaderContents | Out-File -Encoding Ascii -FilePath $OutFile
