[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "$PSScriptRoot\aliases.txt",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 86400)]
    [int]$IntervalSeconds = 30,

    [Parameter(Mandatory = $false)]
    [switch]$LogToFile,

    [Parameter(Mandatory = $false)]
    [string]$LogFilePath = "$PSScriptRoot\mdns_alias_announce.log"
)

$TranscriptStarted = $false
if ($LogToFile) {
    try {
        $logDirectory = Split-Path -Path $LogFilePath -Parent
        if ($logDirectory -and -not (Test-Path -Path $logDirectory)) {
            $null = New-Item -ItemType Directory -Path $logDirectory -Force
        }

        Start-Transcript -Path $LogFilePath -Append -ErrorAction Stop | Out-Null
        $TranscriptStarted = $true
        Write-Host "[+] File logging enabled: $LogFilePath" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "[!] Failed to enable file logging at '$LogFilePath': $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------
# Load and Validate the Input File
# ---------------------------------------------------------------
if (-not (Test-Path -Path $FilePath)) {
    Write-Error "[-] Configuration file not found at: $FilePath"
    return
}

# Load names, skip blank lines, and skip comment lines starting with '#'
$CustomNames = Get-Content -Path $FilePath |
    Where-Object { $_.Trim() -and -not $_.StartsWith("#") } |
    ForEach-Object { $_.Trim() }

if ($CustomNames.Count -eq 0) {
    Write-Warning "[!] The configuration file is empty or only contains comments."
    return
}

function Normalize-LocalName ([string]$Name) {
    $trimmed = $Name.Trim().TrimEnd('.')
    if ($trimmed -notlike "*.local") {
        return "$trimmed.local"
    }
    return $trimmed
}

$PublishedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($name in $CustomNames) {
    $null = $PublishedNames.Add((Normalize-LocalName $name))
}

# ---------------------------------------------------------------
# Core mDNS Protocol Definitions
# ---------------------------------------------------------------
$mDNSAddress = [System.Net.IPAddress]::Parse("224.0.0.251")
$mDNSv6Address = [System.Net.IPAddress]::Parse("ff02::fb")
$mDNSPort    = 5353

function Get-PrimaryIPv4Info {
    # Prefer the interface used by the default IPv4 route.
    $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1

    if ($defaultRoute) {
        $candidate = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -and
                $_.IPAddress -ne "127.0.0.1" -and
                -not $_.IPAddress.StartsWith("169.254.")
            } |
            Select-Object -First 1

        if ($candidate) {
            return [pscustomobject]@{
                IPAddress = $candidate.IPAddress
                InterfaceIndex = $candidate.InterfaceIndex
                InterfaceAlias = $candidate.InterfaceAlias
            }
        }
    }

    # Fallback: first usable non-loopback/non-APIPA IPv4 address.
    $fallback = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -and
            $_.IPAddress -ne "127.0.0.1" -and
            -not $_.IPAddress.StartsWith("169.254.")
        } |
        Select-Object -First 1

    if ($fallback) {
        return [pscustomobject]@{
            IPAddress = $fallback.IPAddress
            InterfaceIndex = $fallback.InterfaceIndex
            InterfaceAlias = $fallback.InterfaceAlias
        }
    }

    return $null
}

$PrimaryIPv4 = Get-PrimaryIPv4Info
$LocalIP = if ($PrimaryIPv4) { $PrimaryIPv4.IPAddress } else { $null }

if (-not $LocalIP) {
    Write-Error "[-] Could not determine a valid local IPv4 address."
    return
}

$IpBytes = [System.Net.IPAddress]::Parse($LocalIP).GetAddressBytes()

function Get-PrimaryIPv6Address ([int]$InterfaceIndex) {
    $candidate = Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -and
            $_.IPAddress -ne "::1" -and
            -not $_.IPAddress.StartsWith("fe80:")
        } |
        Select-Object -First 1 -ExpandProperty IPAddress

    return $candidate
}

$LocalIPv6 = $null
$IPv6Bytes = $null
if ($PrimaryIPv4) {
    $LocalIPv6 = Get-PrimaryIPv6Address -InterfaceIndex $PrimaryIPv4.InterfaceIndex
    if ($LocalIPv6) {
        $IPv6Bytes = [System.Net.IPAddress]::Parse($LocalIPv6).GetAddressBytes()
    }
}

Write-Host "[+] Initializing mDNS Broadcaster..." -ForegroundColor Cyan
Write-Host "[+] Loaded $($CustomNames.Count) aliases from: $FilePath" -ForegroundColor Cyan
Write-Host "[+] Binding Names to Local IP: $LocalIP" -ForegroundColor Green
Write-Host "[+] Selected Interface: $($PrimaryIPv4.InterfaceAlias) (Index $($PrimaryIPv4.InterfaceIndex))" -ForegroundColor Green
if ($LocalIPv6) {
    Write-Host "[+] IPv6 AAAA support enabled on: $LocalIPv6" -ForegroundColor Green
}
else {
    Write-Host "[+] IPv6 AAAA support disabled (no usable IPv6 found on selected interface)." -ForegroundColor DarkYellow
}

function Show-StartupNetworkProfileCheck {
    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
    if (-not $profiles) {
        Write-Warning "[!] Could not read Windows network profiles for firewall self-check."
        return
    }

    $activeProfiles = $profiles | Where-Object {
        $_.IPv4Connectivity -ne 'Disconnected' -or $_.IPv6Connectivity -ne 'Disconnected'
    }

    if (-not $activeProfiles) {
        $activeProfiles = $profiles
    }

    Write-Host "[+] Startup network profile check:" -ForegroundColor Cyan
    foreach ($profile in $activeProfiles) {
        Write-Host "    - Interface=$($profile.InterfaceAlias), Category=$($profile.NetworkCategory), IPv4=$($profile.IPv4Connectivity)" -ForegroundColor DarkCyan
    }

    $publicProfiles = $activeProfiles | Where-Object { $_.NetworkCategory -eq 'Public' }
    if ($publicProfiles) {
        Write-Warning "[!] One or more active adapters are on Public profile. Inbound mDNS (UDP 5353) is commonly blocked in this profile."
        Write-Warning "[!] If this is a trusted LAN, switch the adapter to Private or add explicit firewall rules for UDP 5353 on Public."
    }
}

Show-StartupNetworkProfileCheck

# Helper function to convert a domain name string to DNS binary label format
function Convert-NameToDNSLabels ($DomainName) {
    $DomainName = Normalize-LocalName $DomainName

    $parts = $DomainName.Split('.')
    $bytes = [System.Collections.Generic.List[byte]]::new()
    foreach ($part in $parts) {
        $partBytes = [System.Text.Encoding]::ASCII.GetBytes($part)
        $bytes.Add([byte]$partBytes.Length)
        $bytes.AddRange($partBytes)
    }
    $bytes.Add(0x00) # End of name marker
    return $bytes.ToArray()
}

function Add-Bytes ([System.Collections.Generic.List[byte]]$Target, [byte[]]$Values) {
    foreach ($value in $Values) {
        $Target.Add($value)
    }
}

function New-AnswerPacket ([string]$Name, [byte[]]$AddressBytes, [UInt16]$RecordType) {
    $packet = [System.Collections.Generic.List[byte]]::new()

    # Transaction ID
    Add-Bytes $packet ([byte[]]@(0x00, 0x00))
    # Flags: 0x8400 (Response, Authoritative Answer, No Error)
    Add-Bytes $packet ([byte[]]@(0x84, 0x00))
    # Questions Count: 0, Answer RRs Count: 1
    Add-Bytes $packet ([byte[]]@(0x00, 0x00, 0x00, 0x01))
    # Authority RRs Count: 0, Additional RRs Count: 0
    Add-Bytes $packet ([byte[]]@(0x00, 0x00, 0x00, 0x00))

    # Answer section
    Add-Bytes $packet ([byte[]](Convert-NameToDNSLabels $Name))
    # Type: A (0x0001) or AAAA (0x001C)
    Add-Bytes $packet ([byte[]]@([byte](($RecordType -shr 8) -band 0xFF), [byte]($RecordType -band 0xFF)))
    # Class: IN with cache-flush bit
    Add-Bytes $packet ([byte[]]@(0x80, 0x01))
    # TTL: 120 seconds
    Add-Bytes $packet ([byte[]]@(0x00, 0x00, 0x00, 0x78))
    # RDLENGTH
    Add-Bytes $packet ([byte[]]@([byte](($AddressBytes.Length -shr 8) -band 0xFF), [byte]($AddressBytes.Length -band 0xFF)))
    # RDATA
    Add-Bytes $packet ([byte[]]$AddressBytes)

    return $packet.ToArray()
}

function Read-DnsName ([byte[]]$Data, [int]$Offset) {
    $labels = [System.Collections.Generic.List[string]]::new()
    $pos = $Offset
    $jumped = $false
    $nextOffset = $Offset
    $seen = [System.Collections.Generic.HashSet[int]]::new()

    while ($pos -lt $Data.Length) {
        if (-not $seen.Add($pos)) {
            break
        }

        $len = [int]$Data[$pos]

        if ($len -eq 0) {
            if (-not $jumped) {
                $nextOffset = $pos + 1
            }
            break
        }

        # DNS compression pointer (11xxxxxx xxxxxxxx)
        if (($len -band 0xC0) -eq 0xC0) {
            if (($pos + 1) -ge $Data.Length) {
                break
            }

            $pointer = (($len -band 0x3F) -shl 8) -bor [int]$Data[$pos + 1]
            if (-not $jumped) {
                $nextOffset = $pos + 2
            }
            $pos = $pointer
            $jumped = $true
            continue
        }

        $start = $pos + 1
        $end = $start + $len
        if ($end -gt $Data.Length) {
            break
        }

        $labels.Add([System.Text.Encoding]::ASCII.GetString($Data, $start, $len))
        $pos = $end

        if (-not $jumped) {
            $nextOffset = $pos
        }
    }

    return @{
        Name = ($labels -join ".")
        NextOffset = $nextOffset
    }
}

function Get-ParsedQueries ([byte[]]$QueryPacket, [System.Collections.Generic.HashSet[string]]$PublishedSet) {
    $queries = [System.Collections.Generic.List[object]]::new()

    if ($QueryPacket.Length -lt 12) {
        return $queries
    }

    $flags = ([int]$QueryPacket[2] -shl 8) -bor [int]$QueryPacket[3]
    $isResponse = ($flags -band 0x8000) -ne 0
    if ($isResponse) {
        return $queries
    }

    $questionCount = ([int]$QueryPacket[4] -shl 8) -bor [int]$QueryPacket[5]
    $offset = 12

    for ($i = 0; $i -lt $questionCount; $i++) {
        $nameInfo = Read-DnsName -Data $QueryPacket -Offset $offset
        $queryName = Normalize-LocalName $nameInfo.Name
        $offset = [int]$nameInfo.NextOffset

        if (($offset + 3) -ge $QueryPacket.Length) {
            break
        }

        $qType = ([int]$QueryPacket[$offset] -shl 8) -bor [int]$QueryPacket[$offset + 1]
        $qClass = ([int]$QueryPacket[$offset + 2] -shl 8) -bor [int]$QueryPacket[$offset + 3]
        $offset += 4

        $wantsUnicast = ($qClass -band 0x8000) -ne 0
        $qClassBase = $qClass -band 0x7FFF
        $classIsIN = $qClassBase -eq 0x0001
        $typeMatches = ($qType -eq 0x0001) -or ($qType -eq 0x001C) -or ($qType -eq 0x00FF)
        $isPublished = $PublishedSet.Contains($queryName)
        $isMatch = $classIsIN -and $typeMatches -and $isPublished

        $queries.Add([pscustomobject]@{
            Name = $queryName
            QType = $qType
            QClass = $qClass
            WantsUnicast = $wantsUnicast
            ClassIsIN = $classIsIN
            TypeMatches = $typeMatches
            IsPublished = $isPublished
            IsMatch = $isMatch
        })
    }

    return $queries
}

# ---------------------------------------------------------------
# Main Announcement Loop
# ---------------------------------------------------------------
$UdpClient = [System.Net.Sockets.UdpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
$UdpClientV6 = $null
$UdpClient.ExclusiveAddressUse = $false
# Enable Address Reuse so it doesn't conflict with Windows native mDNS
$UdpClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
$UdpClient.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, $mDNSPort))
# RFC 6762 requires link-local mDNS packets to use IP TTL 255.
$UdpClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastTimeToLive, 255)
# Pin multicast receive and send to the selected IPv4 interface.
$UdpClient.JoinMulticastGroup($mDNSAddress, [System.Net.IPAddress]::Parse($LocalIP))
$multicastInterfaceBytes = [System.Net.IPAddress]::Parse($LocalIP).GetAddressBytes()
$UdpClient.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastInterface, $multicastInterfaceBytes)
$UdpClient.Client.ReceiveTimeout = 500
$EndPoint = New-Object System.Net.IPEndPoint ($mDNSAddress, $mDNSPort)
$EndPointV6 = [System.Net.IPEndPoint]::new($mDNSv6Address, $mDNSPort)

if ($LocalIPv6) {
    try {
        $UdpClientV6 = [System.Net.Sockets.UdpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $UdpClientV6.ExclusiveAddressUse = $false
        $UdpClientV6.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $UdpClientV6.Client.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Any, $mDNSPort))
        # RFC 6762 requires link-local mDNS packets to use hop limit 255.
        $UdpClientV6.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IPv6, [System.Net.Sockets.SocketOptionName]::HopLimit, 255)
        $UdpClientV6.JoinMulticastGroup($mDNSv6Address, $PrimaryIPv4.InterfaceIndex)
        $UdpClientV6.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IPv6, [System.Net.Sockets.SocketOptionName]::MulticastInterface, $PrimaryIPv4.InterfaceIndex)
        $UdpClientV6.Client.ReceiveTimeout = 500
        Write-Host "[+] IPv6 mDNS transport enabled on ff02::fb (Interface Index $($PrimaryIPv4.InterfaceIndex))" -ForegroundColor Green
    }
    catch {
        $UdpClientV6 = $null
        Write-Warning "[!] Failed to initialize IPv6 mDNS transport: $($_.Exception.Message)"
    }
}

function Handle-IncomingQueryPacket (
    [System.Net.Sockets.UdpClient]$Socket,
    [byte[]]$QueryPacket,
    [System.Net.IPEndPoint]$RemoteEndPoint,
    [System.Net.IPEndPoint]$MulticastEndPoint,
    [System.Collections.Generic.HashSet[string]]$PublishedSet,
    [byte[]]$IPv4AddressBytes,
    [byte[]]$IPv6AddressBytes
) {
    $parsedQueries = Get-ParsedQueries -QueryPacket $QueryPacket -PublishedSet $PublishedSet

    foreach ($query in $parsedQueries) {
        Write-Verbose ("mDNS query from {0}:{1} family={2} name={3} type=0x{4:X4} class=0x{5:X4} qu={6} match={7}" -f $RemoteEndPoint.Address, $RemoteEndPoint.Port, $RemoteEndPoint.AddressFamily, $query.Name, $query.QType, $query.QClass, $query.WantsUnicast, $query.IsMatch)
    }

    $responsesSent = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $matchedQueries = $parsedQueries | Where-Object { $_.IsMatch }

    foreach ($match in $matchedQueries) {
        $responseKey = "$($match.Name)|$($match.WantsUnicast)|$($match.QType)"
        if (-not $responsesSent.Add($responseKey)) {
            continue
        }

        $responses = [System.Collections.Generic.List[object]]::new()

        if ($match.QType -eq 0x0001) {
            $responses.Add([pscustomobject]@{ RecordType = 0x0001; AddressBytes = $IPv4AddressBytes; Label = 'A' })
        }
        elseif ($match.QType -eq 0x001C) {
            if ($IPv6AddressBytes) {
                $responses.Add([pscustomobject]@{ RecordType = 0x001C; AddressBytes = $IPv6AddressBytes; Label = 'AAAA' })
            }
            else {
                Write-Verbose ("mDNS query requested AAAA but no IPv6 address is configured for {0}" -f $match.Name)
            }
        }
        else {
            # ANY query: return all available address families.
            $responses.Add([pscustomobject]@{ RecordType = 0x0001; AddressBytes = $IPv4AddressBytes; Label = 'A' })
            if ($IPv6AddressBytes) {
                $responses.Add([pscustomobject]@{ RecordType = 0x001C; AddressBytes = $IPv6AddressBytes; Label = 'AAAA' })
            }
        }

        foreach ($resp in $responses) {
            $response = New-AnswerPacket -Name $match.Name -AddressBytes $resp.AddressBytes -RecordType $resp.RecordType

            if ($match.WantsUnicast) {
                $null = $Socket.Send($response, $response.Length, $RemoteEndPoint)
                Write-Verbose ("mDNS response path=unicast target={0}:{1} family={2} name={3} type={4}" -f $RemoteEndPoint.Address, $RemoteEndPoint.Port, $RemoteEndPoint.AddressFamily, $match.Name, $resp.Label)
                Write-Host "  -> Responded (unicast $($resp.Label)) for: $($match.Name) to $($RemoteEndPoint.Address):$($RemoteEndPoint.Port)" -ForegroundColor DarkGray
            }
            else {
                $null = $Socket.Send($response, $response.Length, $MulticastEndPoint)
                Write-Verbose ("mDNS response path=multicast target={0}:{1} family={2} name={3} type={4}" -f $MulticastEndPoint.Address, $MulticastEndPoint.Port, $MulticastEndPoint.AddressFamily, $match.Name, $resp.Label)
                Write-Host "  -> Responded (multicast $($resp.Label)) for: $($match.Name)" -ForegroundColor DarkGray
            }
        }
    }
}

try {
    $nextAnnouncement = Get-Date
    $remoteEndPointV4 = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $remoteEndPointV6 = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Any, 0)

    while ($true) {
        $now = Get-Date

        if ($now -ge $nextAnnouncement) {
            Write-Host "[$($now.ToString('HH:mm:ss'))] Sending periodic mDNS announcements..." -ForegroundColor Yellow

            foreach ($name in $PublishedNames) {
                $bufferA = New-AnswerPacket -Name $name -AddressBytes $IpBytes -RecordType 0x0001
                $null = $UdpClient.Send($bufferA, $bufferA.Length, $EndPoint)
                Write-Host "  -> Announced A: $name" -ForegroundColor Gray

                if ($UdpClientV6) {
                    $null = $UdpClientV6.Send($bufferA, $bufferA.Length, $EndPointV6)
                    Write-Host "  -> Announced A (IPv6 mDNS transport): $name" -ForegroundColor Gray
                }

                if ($IPv6Bytes) {
                    $bufferAAAA = New-AnswerPacket -Name $name -AddressBytes $IPv6Bytes -RecordType 0x001C
                    $null = $UdpClient.Send($bufferAAAA, $bufferAAAA.Length, $EndPoint)
                    Write-Host "  -> Announced AAAA: $name" -ForegroundColor Gray

                    if ($UdpClientV6) {
                        $null = $UdpClientV6.Send($bufferAAAA, $bufferAAAA.Length, $EndPointV6)
                        Write-Host "  -> Announced AAAA (IPv6 mDNS transport): $name" -ForegroundColor Gray
                    }
                }
            }

            $nextAnnouncement = (Get-Date).AddSeconds($IntervalSeconds)
        }

        try {
            $queryPacketV4 = $UdpClient.Receive([ref]$remoteEndPointV4)
            Handle-IncomingQueryPacket -Socket $UdpClient -QueryPacket $queryPacketV4 -RemoteEndPoint $remoteEndPointV4 -MulticastEndPoint $EndPoint -PublishedSet $PublishedNames -IPv4AddressBytes $IpBytes -IPv6AddressBytes $IPv6Bytes
        }
        catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::TimedOut) {
                throw
            }
        }

        if ($UdpClientV6) {
            try {
                $queryPacketV6 = $UdpClientV6.Receive([ref]$remoteEndPointV6)
                Handle-IncomingQueryPacket -Socket $UdpClientV6 -QueryPacket $queryPacketV6 -RemoteEndPoint $remoteEndPointV6 -MulticastEndPoint $EndPointV6 -PublishedSet $PublishedNames -IPv4AddressBytes $IpBytes -IPv6AddressBytes $IPv6Bytes
            }
            catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::TimedOut) {
                    throw
                }
            }
        }
    }
}
catch {
    Write-Error $_.Exception.Message
}
finally {
    if ($TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            Write-Warning "[!] Failed to stop transcript logging cleanly: $($_.Exception.Message)"
        }
    }

    $UdpClient.Close()
    if ($UdpClientV6) {
        $UdpClientV6.Close()
    }
    Write-Host "[!] Broadcast stopped. Socket closed." -ForegroundColor Red
}