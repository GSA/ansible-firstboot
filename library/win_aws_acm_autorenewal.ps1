#!powershell

#AnsibleRequires -CSharpUtil Ansible.Basic
#Requires -Module Ansible.ModuleUtils.Legacy

$ErrorActionPreference = "Stop"
trap {
    $module.FailJson("failed", $_)
}

function Find-Certificate {
    param(
        [Parameter(Mandatory=$true)]
        [String]$Hostname,
        [Parameter(Mandatory=$false)]
        [String]$Region="us-east-1"
    )

    $certs = Get-ACMCertificateList -Region $Region
    foreach($c in $certs) {
        $parts = $c.DomainName.Split(".")
        if ($parts.Length -eq -1) { continue }
        if ($parts[0] -eq $Hostname) {
            return $c
        }
    }
    $module.FailJson("failed to locate a valid certificte for hostname: " + $Hostname)
}

function Get-RemoteNotBefore {
    [OutputType([Datetime])]
    param(
        [Parameter(Mandatory=$true)]
        [String]$Arn,
        [Parameter(Mandatory=$false)]
        [String]$Region="us-east-1"
    )

    $resp = Get-ACMCertificate -CertificateArn $Arn -Region $Region
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                [System.Text.Encoding]::ASCII.GetBytes($resp.Certificate))
    return $cert.NotBefore
}

function Get-LocalNotBefore {
   [OutputType([Datetime])]
   param(
      [Parameter(Mandatory=$true)]
      [String]$Hostname
   )
   $loc = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
   $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($loc)

   $col = @()
   try {
       $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

       foreach($c in $store.Certificates) {
           $parts = $c.Subject.Split(".")
           if ($parts[0] -eq "CN=$Hostname") {
               $col += $c
           }
       }
   }
   finally {
       $store.Close()
   }

   if ($col.Length -eq 0) {
       return [DateTime]::MinValue
   }

   $selected = $col | Sort-Object -Property NotBefore -Descending | Select-Object -First 1

   return $selected.NotBefore
}

function Export-Certificate {
    param(
        [Parameter(Mandatory=$true)]
        [String]$Arn,
        [Parameter(Mandatory=$true)]
        [String]$Passphrase,
        [Parameter(Mandatory=$false)]
        [String]$Region="us-east-1",
        [Parameter(Mandatory=$true)]
        [String]$Path,
        [Parameter(Mandatory=$true)]
        [String]$OpenSSL
    )

    $resp = Export-ACMCertificate -CertificateArn $Arn -Region $Region -Passphrase $Passphrase

    # Create certificates directory
    New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    # Create certs.pem and key.pem
    $certsPath = [System.IO.Path]::Combine($Path, "certs.pem")
    $resp.Certificate + $resp.CertificateChain | Out-File -FilePath $certsPath -Encoding ascii

    $keyPath = [System.IO.Path]::Combine($Path, "key.pem")
    $resp.PrivateKey | Out-File -FilePath $keyPath -Encoding ascii

    # Create Passphrase
    $passPath = [System.IO.Path]::Combine($Path, "p")
    $Passphrase | Out-File -FilePath $passPath -Encoding ascii

    # OpenSSL remove passphrase
    $uncPath = [System.IO.Path]::Combine($Path, "unc.pem")
    Start-Process -FilePath $OpenSSL -ArgumentList @("pkcs8", "-in", $keyPath, "-out", $uncPath, "-passin", "file:${passPath}") -Wait

    # OpenSSL creates PFX
    $pfxPath = [System.IO.Path]::Combine($Path, "machine.pfx")
    Start-Process -FilePath $OpenSSL -ArgumentList @("pkcs12", "-export", "-in", $certsPath, "-inkey", $uncPath, "-out", $pfxPath, "-passout", "file:${passPath}") -Wait

    # Cleanup non-password protected PEM and passphrase files
    Remove-Item -Path @($certsPath, $keyPath, $uncPath, $passPath) -Force | Out-Null

    # Register certificates/keys in Windows Certificate Stores
    Export-PFXtoStore -Path $pfxPath -Passphrase $Passphrase
}

function Export-PFXtoStore {
    param(
        [Parameter(Mandatory=$true)]
        [String]$Path,
        [Parameter(Mandatory=$true)]
        [String]$Passphrase
    )

    $col = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $col.Import($Path, $Passphrase, 22) # 22 = Exportable, MachineKeySet, PersistKeySet

    foreach($c in $col) {
        Write-Host ([String]::Format("Loading certificate -> Issuer: {0}, Subject: {1}, HasPrivateKey: {2}", $c.Issuer, $c.Subject, $c.HasPrivateKey))
        $store = Get-Store -Certificate $c

        $store.Open("ReadWrite")
        $store.Add($c)
        $store.Close()
    }
}

function Get-Store {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Store])]
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $loc = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine

    if ($Certificate.HasPrivateKey) {
        return [System.Security.Cryptography.X509Certificates.X509Store]::new("MY", $loc)
    }
    if ($Certificate.Subject -eq $Certificate.Issuer) {
        return [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", $loc)
    }
    return [System.Security.Cryptography.X509Certificates.X509Store]::new("CertificateAuthority", $loc)
}

$spec = @{
    options = @{
        hostname = @{ type = 'str'; required = $true }
        passphrase = @{ type = 'str'; required = $true }
        basepath = @{ type = 'str'; default = 'C:\ProgramData\certificates' }
        region = @{ type = 'str'; default = 'us-east-1' }
        openssl = @{ type = 'str'; default = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

# Find the matching certificate for this host
$cert = Find-Certificate -Hostname $module.params.hostname -Region $module.params.region

# Grab the 'NotBefore' dates from the remote certificate and the local certificate
$rdate = Get-RemoteNotBefore -Arn $cert.CertificateArn -Region $module.params.region
$ldate = Get-LocalNotBefore -Hostname $module.params.hostname

$changed = $false
if ($rdate -gt $ldate) { # If remote date is greater than local date, perform an export
    Export-Certificate -Arn $cert.CertificateArn -Passphrase $module.params.passphrase -Region $module.params.region `
    -Path $module.params.basepath -OpenSSL $module.params.openssl
    $changed = $true
}

$result = New-Object psobject @{
    meta    = $module.params
    changed = $changed
}

Exit-Json $result;
