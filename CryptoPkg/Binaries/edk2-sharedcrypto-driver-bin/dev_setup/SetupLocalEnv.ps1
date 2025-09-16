# SetupLocalEnv.ps1
# Script to create symbolic links for SharedCryptLib
# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "Please restart PowerShell as Administrator and run this script again." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To do this:" -ForegroundColor Cyan
    Write-Host "1. Close this PowerShell window" -ForegroundColor White
    Write-Host "2. Right-click on PowerShell" -ForegroundColor White
    Write-Host "3. Select 'Run as Administrator'" -ForegroundColor White
    Write-Host "4. Navigate back to this directory and run the script again" -ForegroundColor White
    exit 1
}

Write-Host "Running with Administrator privileges..." -ForegroundColor Green
Write-Host ""

# Environment Settings
# TODO: add these to a .env file or similar for better management
$baseDir = "C:\git\flickdm"
$projectDir = "MTP_DEMO_SHARED_CRYPTO"

# Define source directory
$sourceDir = "$baseDir\mu_crypto_release\"
$cryptoPkgDir = "$baseDir\$projectDir\MU_BASECORE\CryptoPkg"
$binariesDir = "$cryptoPkgDir\Binaries"
# Define symlink mappings organized by category
$symlinkDefinitions = @{
    # Binary files
    Binaries = @{
        BasePath = "$binariesDir\edk2-sharedcrypto-driver-bin\bin\shared"
        Links = @(
            @{ Source = "\Build\CryptoPkg\DEBUG_VS2022\X64\SharedCryptoMmBin.efi"; Name = "SharedCryptoMmBin.efi" }
            @{ Source = "\CryptoPkg\SharedCryptoBin\Support\SharedCryptoMm.inf"; Name = "SharedCryptoMmBin.inf" }
            @{ Source = "\Build\CryptoPkg\DEBUG_VS2022\X64\CryptoPkg\SharedCryptoBin\SharedCryptoMmBin\OUTPUT\SharedCryptoMmBin.depex"; Name = "SharedCryptoMmBin.depex" }
        )
    }
    
    # Driver source
    Driver = @{
        BasePath = "$binariesDir\edk2-sharedcrypto-driver-bin\src"
        Links = @(
            @{ Source = "CryptoPkg\Driver"; Name = "driver" }
        )
    }
    
    # Support files (FDF/DSC includes)
    SupportFiles = @{
        BasePath = "$binariesDir\edk2-sharedcrypto-driver-bin"
        Links = @(
            @{ Source = "\CryptoPkg\SharedCryptoBin\Support\SharedCrypto.CryptoBinary.inc.fdf"; Name = "SharedCrypto.CryptoBinary.inc.fdf" }
            @{ Source = "\CryptoPkg\SharedCryptoBin\Support\SharedCrypto.Dxe.inc.fdf"; Name = "SharedCrypto.Dxe.inc.fdf" }
            @{ Source = "\CryptoPkg\SharedCryptoBin\Support\SharedCrypto.inc.dsc"; Name = "SharedCrypto.inc.dsc" }
            @{ Source = "\CryptoPkg\SharedCryptoBin\Support\SharedCrypto.StandaloneMm.inc.fdf"; Name = "SharedCrypto.StandaloneMm.inc.fdf" }
        )
    }
    
    # Include files
    IncludeLibrary = @{
        BasePath = "$cryptoPkgDir\Include\Library"
        Links = @(
            @{ Source = "\CryptoPkg\Include\Library\SharedCryptoDefinitions.h"; Name = "SharedCryptoDefinitions.h" }
            @{ Source = "\CryptoPkg\Include\Library\SharedCryptoDependencySupport.h"; Name = "SharedCryptoDependencySupport.h" }
            @{ Source = "\CryptoPkg\Include\Library\SharedCryptoLib.h"; Name = "SharedCryptoLib.h" }
        )
    }
    
    # Protocol includes
    IncludeProtocol = @{
        BasePath = "$cryptoPkgDir\Include\Protocol"
        Links = @(
            @{ Source = "\CryptoPkg\Include\Protocol\SharedCryptoProtocol.h"; Name = "SharedCryptoProtocol.h" }
        )
    }
    
    # Library implementation
    LibraryImplementation = @{
        BasePath = "$cryptoPkgDir\Library\BaseCryptLibOnProtocolPpi"
        Links = @(
            @{ Source = "\CryptoPkg\Library\BaseCryptLibOnProtocolPpi\SharedCryptoLib.c"; Name = "SharedCryptoLib.c" }
        )
    }


}

# Convert organized structure to flat symlink array
$symlinks = @()
foreach ($category in $symlinkDefinitions.GetEnumerator()) {
    $basePath = $category.Value.BasePath
    foreach ($link in $category.Value.Links) {
        $symlinks += @{
            Source = $link.Source
            Destination = Join-Path $basePath $link.Name
        }
    }
}

# Function to create symbolic links
function New-SymbolicLink {
    param(
        [string]$LinkPath,
        [string]$TargetPath
    )
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Warning "This script requires Administrator privileges to create symbolic links."
        return $false
    }
    
    # Remove existing link if it exists
    if (Test-Path $LinkPath) {
        Write-Host "Removing existing path: $LinkPath" -ForegroundColor Yellow
        Remove-Item $LinkPath -Force -Recurse
    }
    
    # Create the symbolic link
    try {
        New-Item -ItemType SymbolicLink -Path $LinkPath -Target $TargetPath -Force | Out-Null
        Write-Host "Created symlink: $LinkPath -> $TargetPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to create symlink: $_"
        return $false
    }
}

# Main execution
Write-Host "Setting up symbolic links for SharedCryptLib..." -ForegroundColor Cyan
Write-Host "Source directory: $sourceDir" -ForegroundColor Cyan
Write-Host ""

# Verify source directory exists
if (-not (Test-Path $sourceDir)) {
    Write-Error "Source directory does not exist: $sourceDir"
    exit 1
}

# Create each symbolic link
$successCount = 0
$failCount = 0

foreach ($link in $symlinks) {
    $sourcePath = Join-Path $sourceDir $link.Source
    $destPath = $link.Destination
    
    if (New-SymbolicLink -LinkPath $destPath -TargetPath $sourcePath) {
        $successCount++
    }
    else {
        $failCount++
    }
}

Write-Host ""
Write-Host "Setup complete!" -ForegroundColor Cyan
Write-Host "Successfully created: $successCount symlinks" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "Failed to create: $failCount symlinks" -ForegroundColor Red
}