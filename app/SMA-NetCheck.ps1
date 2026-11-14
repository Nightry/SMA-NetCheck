<#
.SYNOPSIS
    SMA NetCheck - przenośne narzędzie diagnostyki sieci dla instalatorów i wsparcia SMA.
    Portable network diagnostic tool for SMA installers and support (PL / EN / DE).

.DESCRIPTION
    Sprawdza z urządzenia testującego (Windows) podłączonego do tej samej sieci co urządzenia SMA:
      1. Połączenie z portalami SMA (DNS, porty TCP, TLS/HTTPS, NTP, inspekcja SSL, proxy).
      2. Osiągalność urządzeń w sieci lokalnej po hostname/IP (DNS, mDNS, NetBIOS/LLMNR,
         ping, ARP/MAC, porty 443/80/502, Speedwire unicast) wraz z analizą podsieci.
      3. Skanowanie podsieci: SMA po nazwie (SMA...), po MAC, Speedwire + lista wszystkich urządzeń.
      4. Multicast Speedwire (239.12.255.254:9522) - Energy Meter / Home Manager / falowniki.
    Generuje raport HTML. Teksty w pliku SMA-NetCheck.lang.ps1 (PL/EN/DE).

.EXAMPLE
    .\SMA-NetCheck.ps1
    .\SMA-NetCheck.ps1 -Mode Full -Interface Ethernet -Device SMA3012345678,192.168.1.50 -Language EN
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Portal', 'Local', 'Scan', 'Multicast', 'Full')]
    [string]$Mode = 'Menu',
    # Alias (nazwa), indeks lub IP karty sieciowej.
    [string]$Interface,
    # Hostname'y lub adresy IP urządzeń SMA do sprawdzenia (tryb Local/Full).
    [string[]]$Device,
    # Czas nasłuchu multicast w sekundach (300+ wykrywa problem z IGMP snooping).
    [int]$ListenSeconds = 20,
    # Własny zakres skanowania (zamiast podsieci karty), np. 192.168.1.1-255, 192.168.1.10-192.168.1.50, 192.168.1.0/24
    [string]$ScanRange,
    # Ścieżka raportu HTML (domyślnie folder 'Reports' obok skryptu).
    [string]$ReportPath,
    [switch]$NoReport,
    # Dodaj tymczasową regułę firewall (UDP 9522/5353) na czas testu - wymaga admina.
    [switch]$AddFirewallRule,
    # Język: PL / EN / DE (puste = zapisany wybór, a przy pierwszym uruchomieniu EN).
    [ValidateSet('', 'PL', 'EN', 'DE')]
    [string]$Language = ''
)

# =====================================================================================
#  KONFIGURACJA - tu można dopisywać/zmieniać cele testów (nazwy: klucze z pliku językowego)
# =====================================================================================
$script:Version = '1.1.0'

# Type: TLS (TCP + handshake TLS + odpowiedź HTTP), TCP (samo połączenie), NTP (UDP 123)
$script:PortalTargets = @(
    @{ Key = 'tgt.ennexos'; HostName = 'ennexos.sunnyportal.com';    Port = 443;  Type = 'TLS'; ForKey = 'for.ennexos' }
    @{ Key = 'tgt.ldm';     HostName = 'ldm-devapi.sunnyportal.com'; Port = 443;  Type = 'TLS'; ForKey = 'for.ennexosdev' }
    @{ Key = 'tgt.update';  HostName = 'update.sunnyportal.de';      Port = 443;  Type = 'TLS'; ForKey = 'for.allnew' }
    @{ Key = 'tgt.ntp';     HostName = 'ntp.sunny-portal.com';       Port = 123;  Type = 'NTP'; ForKey = 'for.ntp' }
    @{ Key = 'tgt.wco';     HostName = 'wco.sunnyportal.com';        Port = 9524; Type = 'TCP'; ForKey = 'for.wco' }
    @{ Key = 'tgt.classic'; HostName = 'www.sunnyportal.com';        Port = 443;  Type = 'TLS'; ForKey = 'for.classic' }
)
# Cele kontrolne - pozwalają odróżnić "brak Internetu" od "blokady tylko SMA"
$script:ControlTargets = @(
    @{ Key = 'tgt.ctrl.ms'; HostName = 'www.microsoft.com'; Port = 443; Type = 'TLS'; ForKey = 'for.control'; Control = $true }
    @{ Key = 'tgt.ctrl.cf'; HostName = '1.1.1.1';           Port = 443; Type = 'TCP'; ForKey = 'for.control'; Control = $true }
)
$script:PublicDns      = @('8.8.8.8', '1.1.1.1')
# Nazwa używana do sprawdzenia, czy serwery DNS odpowiadają (nowy portal ennexOS; classic będzie wygaszany)
$script:DnsTestName    = 'ennexos.sunnyportal.com'
# Strona ze statusem serwerów SMA (awarie / prace serwisowe po stronie SMA)
$script:StatusPageUrl  = 'https://sunnyportal.statuspage.io/'
# Prefiksy MAC (OUI) z rejestru IEEE: producent -> lista prefiksów.
# SMA: 00-40-AD (SMA Regelsysteme GmbH - dawna nazwa SMA), 00-15-BB (SMA Solar Technology AG),
#      AC-19-9F (prefiks używany przez część falowników SMA)
$script:VendorOui      = [ordered]@{
    'SMA' = @('00-40-AD', '00-15-BB', 'AC-19-9F')
}
# Hostname urządzenia SMA: "SMA" + numer seryjny (np. SMA3012345678). Nie łapie nazw typu "Smart-TV".
$script:SmaHostPattern = '^sma(?![a-z])'
$script:SpeedwireGroup = '239.12.255.254'
$script:SpeedwirePort  = 9522
$script:LocalTcpPorts  = @(
    @{ Port = 443; Key = 'port.https' }
    @{ Port = 80;  Key = 'port.http' }
    @{ Port = 502; Key = 'port.modbus' }
)
# Fragmenty nazw wystawców certyfikatów typowych dla inspekcji SSL (firewalle/proxy/AV)
$script:SslInspectionPattern = 'Fortinet|FortiGate|Palo Alto|Sophos|Zscaler|Check ?Point|Barracuda|WatchGuard|Cisco Umbrella|Kaspersky|ESET|Avast|AVG|Bitdefender|Forcepoint|McAfee|Netskope|Untangle|pfSense|Squid|Proxy|Firewall|Inspection'

# =====================================================================================
#  STAN
# =====================================================================================
$script:Results        = New-Object System.Collections.Generic.List[object]
$script:Adapter        = $null
$script:AllAdapters    = @()
$script:CheckedAdapter = @{}
$script:TempRuleName   = 'SMA-NetCheck-Temp'
$script:TempRuleAdded  = $false
$script:IsAdmin        = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Interactive    = ($Mode -eq 'Menu')
$script:Sync           = $null    # ustawiane przez GUI: kolejka wyników + status/postęp
$script:YesPattern     = '^[tTyYjJ]'

# =====================================================================================
#  JĘZYK
# =====================================================================================
$script:LangCodes = @('PL', 'EN', 'DE')
$script:Lang      = 'EN'
$script:LangIndex = 1
$script:LangFile  = Join-Path $PSScriptRoot 'SMA-NetCheck.lang.ps1'
# Raporty trafiają do folderu "Reports" obok Start-SMA-NetCheck.cmd (o poziom wyżej niż folder "app")
$script:ReportsDir = Join-Path $(if ((Split-Path $PSScriptRoot -Leaf) -eq 'app') { Split-Path $PSScriptRoot -Parent } else { $PSScriptRoot }) 'Reports'
$script:Strings   = @{}
if (Test-Path $script:LangFile) { $script:Strings = & $script:LangFile }
else { Write-Warning "Missing language file: $($script:LangFile)" }

# Tłumaczenie: T 'klucz' [argumenty dla {0} {1} ...]
function T([string]$Key) {
    $e = $script:Strings[$Key]
    if (-not $e) { return "[$Key]" }
    $s = $e[$script:LangIndex]
    if (-not $s) { $s = $e[1] }
    $s = $s.Replace('\n', "`n")
    if ($args.Count -gt 0) { $s = $s -f $args }
    return $s
}

function Set-NcLanguage([string]$Lang) {
    $i = [array]::IndexOf($script:LangCodes, ([string]$Lang).ToUpper())
    if ($i -lt 0) { $i = 1 }
    $script:Lang = $script:LangCodes[$i]
    $script:LangIndex = $i
}

function Get-NcSettingsPaths {
    @((Join-Path $PSScriptRoot 'SMA-NetCheck.settings.json'), (Join-Path $env:APPDATA 'SMA-NetCheck\settings.json'))
}

function Get-NcDefaultLanguage {
    foreach ($p in Get-NcSettingsPaths) {
        try {
            if (Test-Path $p) {
                $s = Get-Content $p -Raw -ErrorAction Stop | ConvertFrom-Json
                if ($s.Language -and $script:LangCodes -contains $s.Language) { return $s.Language }
            }
        } catch { }
    }
    # Pierwsze uruchomienie (brak zapisanego wyboru): zawsze angielski
    return 'EN'
}

function Save-NcLanguage([string]$Lang) {
    $json = (@{ Language = $Lang } | ConvertTo-Json)
    foreach ($p in Get-NcSettingsPaths) {
        try {
            $d = Split-Path $p
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -ErrorAction Stop | Out-Null }
            [IO.File]::WriteAllText($p, $json)
            return $true
        } catch { }
    }
    return $false
}

Set-NcLanguage $(if ($Language) { $Language } else { Get-NcDefaultLanguage })

# =====================================================================================
#  WYJŚCIE / WYNIKI
# =====================================================================================
function Enable-NcGuiMode($Sync) {
    # Wywoływane przez GUI w wątku tle - ustawia zmienne w zakresie używanym przez funkcje testów
    $script:Sync = $Sync
    $script:Interactive = $false
}

function Set-NcStatus([string]$Text, [int]$Percent = -1) {
    if ($script:Sync) { $script:Sync.Status = $Text; $script:Sync.Progress = $Percent }
}

function Write-Section([string]$Title) {
    Set-NcStatus $Title
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Write-Sub([string]$Title) {
    Set-NcStatus $Title
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor White
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Name,
        [ValidateSet('OK', 'WARN', 'FAIL', 'INFO')][string]$Status,
        [string]$Detail = '',
        [string]$Hint = ''
    )
    $r = [pscustomobject]@{
        Time = (Get-Date); Category = $Category; Name = $Name
        Status = $Status; Detail = $Detail; Hint = $Hint
        Adapter = $(if ($script:Adapter) { "$($script:Adapter.Alias) ($($script:Adapter.IP))" } else { '' })
    }
    [void]$script:Results.Add($r)
    if ($script:Sync) { $script:Sync.Queue.Enqueue($r); return }
    $color = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Status]
    Write-Host ('[{0,-6}] ' -f (T "tag.$($Status.ToLower())")) -ForegroundColor $color -NoNewline
    Write-Host $Name -NoNewline
    if ($Detail) { Write-Host " - $Detail" -ForegroundColor Gray } else { Write-Host '' }
    if ($Hint) {
        foreach ($l in ($Hint -split "`n")) { Write-Host "          -> $l" -ForegroundColor DarkYellow }
    }
}

# =====================================================================================
#  NARZĘDZIA IP
# =====================================================================================
function ConvertTo-UInt32([string]$Ip) {
    $b = ([Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}

function ConvertFrom-UInt32([uint32]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($b)
    return ([Net.IPAddress]$b).ToString()
}

function Get-MaskValue([int]$Prefix) {
    if ($Prefix -le 0) { return [uint32]0 }
    return [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Prefix))
}

function Get-MaskString([int]$Prefix) { ConvertFrom-UInt32 (Get-MaskValue $Prefix) }

function Get-NetworkAddress([string]$Ip, [int]$Prefix) {
    ConvertFrom-UInt32 ([uint32]((ConvertTo-UInt32 $Ip) -band (Get-MaskValue $Prefix)))
}

function Test-InSubnet([string]$Ip, [string]$NetIp, [int]$Prefix) {
    $m = Get-MaskValue $Prefix
    return (((ConvertTo-UInt32 $Ip) -band $m) -eq ((ConvertTo-UInt32 $NetIp) -band $m))
}

function Test-IsIPv4([string]$Text) {
    $a = $null
    return ([Net.IPAddress]::TryParse($Text, [ref]$a) -and $a.AddressFamily -eq 'InterNetwork' -and $Text -match '^\d+\.\d+\.\d+\.\d+$')
}

function Get-IpRangeList([string]$Text, [int]$MaxCount = 1024) {
    # Zakres IP wpisany ręcznie. Obsługiwane formy (można łączyć przecinkiem / spacją / w nowych liniach):
    #   192.168.1.1-255   192.168.1.10-192.168.1.50   192.168.1.0/24   192.168.1.20
    $set = New-Object 'System.Collections.Generic.HashSet[uint32]'
    $parts = @(([string]$Text) -split '[,;\s]+' | Where-Object { $_ })
    if ($parts.Count -eq 0) { return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'range.empty') } }
    foreach ($p in $parts) {
        $from = $null; $to = $null
        if ($p -match '^(\d+\.\d+\.\d+\.\d+)/(\d{1,2})$' -and (Test-IsIPv4 $Matches[1]) -and [int]$Matches[2] -le 32) {
            $pre = [int]$Matches[2]; $m = Get-MaskValue $pre
            $net = (ConvertTo-UInt32 $Matches[1]) -band $m
            $bc = $net -bor ([uint32]([uint32]::MaxValue -bxor $m))
            if ($pre -le 30) { $from = $net + 1; $to = $bc - 1 } else { $from = $net; $to = $bc }
        } elseif ($p -match '^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$' -and (Test-IsIPv4 "$($Matches[1]).$($Matches[2])") -and [int]$Matches[3] -le 255) {
            $from = ConvertTo-UInt32 "$($Matches[1]).$($Matches[2])"; $to = ConvertTo-UInt32 "$($Matches[1]).$($Matches[3])"
        } elseif ($p -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$' -and (Test-IsIPv4 $Matches[1]) -and (Test-IsIPv4 $Matches[2])) {
            $from = ConvertTo-UInt32 $Matches[1]; $to = ConvertTo-UInt32 $Matches[2]
        } elseif (Test-IsIPv4 $p) {
            $from = ConvertTo-UInt32 $p; $to = $from
        } else {
            return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'range.invalid' $p) }
        }
        if ($to -lt $from) { return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'range.invalid' $p) } }
        if (($to - $from + 1) + $set.Count -gt $MaxCount) { return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'range.toobig' $MaxCount) } }
        for ($v = [uint64]$from; $v -le $to; $v++) { [void]$set.Add([uint32]$v) }
    }
    $ips = @($set | Sort-Object | ForEach-Object { ConvertFrom-UInt32 $_ })
    return [pscustomobject]@{ Ok = $true; IPs = $ips; Error = $null }
}

function Test-IsPrivateIp([string]$Ip) {
    return ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.0\.0\.0)')
}

function Get-MacVendor([string]$Mac) {
    # Zwraca nazwę producenta z $script:VendorOui (np. 'SMA') albo $null
    if (-not $Mac) { return $null }
    $m = $Mac.ToUpper().Replace(':', '-')
    foreach ($v in $script:VendorOui.Keys) {
        foreach ($o in $script:VendorOui[$v]) { if ($m.StartsWith($o)) { return $v } }
    }
    return $null
}

function Test-IsSmaMac([string]$Mac) { return [bool](Get-MacVendor $Mac) }

function Get-VendorOuiText {
    # np. "SMA 00:40:AD, 00:15:BB, AC:19:9F"
    (@($script:VendorOui.Keys | ForEach-Object { "$_ " + (($script:VendorOui[$_] | ForEach-Object { $_.Replace('-', ':') }) -join ', ') })) -join '; '
}

function Test-IsSmaHostName([string]$Name) {
    return ($Name -and ($Name.Split('.')[0] -match $script:SmaHostPattern))
}

function Get-SocketErrorText($ErrorObject) {
    $ex = $ErrorObject
    if ($ex -is [Management.Automation.ErrorRecord]) { $ex = $ex.Exception }
    while ($ex.InnerException -and -not ($ex -is [Net.Sockets.SocketException])) { $ex = $ex.InnerException }
    if ($ex -is [Net.Sockets.SocketException]) { return [string]$ex.SocketErrorCode }
    return $ex.Message
}

function Get-TcpErrorText([string]$Code) {
    $k = "tcp.$Code"
    if ($script:Strings.ContainsKey($k)) { return (T $k) }
    return $Code
}

function Format-Value($Value) {
    if ($Value) { return [string]$Value }
    return (T 'word.none')
}

# =====================================================================================
#  KARTY SIECIOWE
# =====================================================================================
function Get-AdapterList {
    $list = @()
    $configs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)
    foreach ($c in $configs) {
        if (-not $c.IPv4Address) { continue }
        if (-not $c.NetAdapter -or $c.NetAdapter.Status -ne 'Up') { continue }
        $gw  = @($c.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) | Select-Object -First 1
        $dns = @($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
        $ipif = Get-NetIPInterface -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $prof = Get-NetConnectionProfile -InterfaceIndex $c.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
        $desc = [string]$c.InterfaceDescription
        $media = [string]$c.NetAdapter.PhysicalMediaType
        $v6 = @(@($c.IPv6Address) + @($c.IPv6LinkLocalAddress) | Where-Object { $_ } | ForEach-Object { ($_.IPAddress -split '%')[0] })
        $v6Gw = @($c.IPv6DefaultGateway | ForEach-Object { $_.NextHop }) | Select-Object -First 1
        foreach ($ip in @($c.IPv4Address)) {
            $list += [pscustomobject]@{
                Index       = $c.InterfaceIndex
                Alias       = $c.InterfaceAlias
                Description = $desc
                IP          = $ip.IPAddress
                Prefix      = [int]$ip.PrefixLength
                Mask        = Get-MaskString ([int]$ip.PrefixLength)
                Network     = Get-NetworkAddress $ip.IPAddress ([int]$ip.PrefixLength)
                Gateway     = $gw
                Dns         = $dns
                Dhcp        = $(if ($ipif) { [string]$ipif.Dhcp } else { '?' })
                Mac         = $c.NetAdapter.MacAddress
                LinkSpeed   = $c.NetAdapter.LinkSpeed
                Wireless    = ($media -match '802\.11|Wireless|Native 802' -or $desc -match 'Wi-?Fi|Wireless|WLAN|802\.11')
                Virtual     = ($desc -match 'Virtual|VPN|Hyper-V|VMware|VirtualBox|TAP-|WireGuard|Tunnel|Fortinet|AnyConnect|GlobalProtect|Npcap|Loopback|Tailscale|ZeroTier|OpenVPN')
                Category    = $(if ($prof) { [string]$prof.NetworkCategory } else { '?' })
                Profile     = $(if ($prof) { [string]$prof.Name } else { '' })
                IPv6        = $v6
                IPv6Gateway = $v6Gw
            }
        }
    }
    return $list
}

function Get-DefaultAdapter($List) {
    $List | Sort-Object @{ e = { if ($_.Gateway) { 0 } else { 1 } } },
                        @{ e = { if ($_.Virtual) { 1 } else { 0 } } },
                        @{ e = { if ($_.Wireless) { 1 } else { 0 } } },
                        @{ e = { if ($_.IP -like '169.254.*') { 1 } else { 0 } } } |
        Select-Object -First 1
}

function Show-AdapterTable($List) {
    $i = 1
    foreach ($a in $List) {
        $flags = @()
        if ($a.Wireless) { $flags += (T 'flag.wifi') }
        if ($a.Virtual)  { $flags += (T 'flag.virtual') }
        if (-not $a.Gateway) { $flags += (T 'flag.nogw') }
        if ($a.IP -like '169.254.*') { $flags += (T 'flag.apipa') }
        $mark = if ($script:Adapter -and $script:Adapter.Index -eq $a.Index -and $script:Adapter.IP -eq $a.IP) { '*' } else { ' ' }
        Write-Host (" {0}{1,2}. {2,-28} {3,-18} {4}: {5,-15} {6}" -f $mark, $i, $a.Alias, "$($a.IP)/$($a.Prefix)", (T 'word.gateway'), $(if ($a.Gateway) { $a.Gateway } else { '-' }), ($flags -join ', '))
        Write-Host ("        {0}" -f $a.Description) -ForegroundColor DarkGray
        $i++
    }
}

function Select-Adapter {
    param([switch]$Ask)
    $script:AllAdapters = @(Get-AdapterList)
    if ($script:AllAdapters.Count -eq 0) {
        Write-Host (T 'adapter.none') -ForegroundColor Red
        return $null
    }
    if ($Interface -and -not $Ask) {
        $m = $script:AllAdapters | Where-Object { "$($_.Index)" -eq $Interface -or $_.Alias -like $Interface -or $_.IP -eq $Interface } | Select-Object -First 1
        if ($m) { return $m }
        Write-Host (T 'adapter.notfound' $Interface) -ForegroundColor Yellow
    }
    $def = Get-DefaultAdapter $script:AllAdapters
    if (-not $Ask) { return $def }

    Write-Section (T 'sec.adapterSelect')
    Show-AdapterTable $script:AllAdapters
    $defIdx = [array]::IndexOf($script:AllAdapters, $def) + 1
    $ans = Read-Host (T 'prompt.adapter' $defIdx)
    if ([string]::IsNullOrWhiteSpace($ans)) { return $def }
    $n = 0
    if ([int]::TryParse($ans, [ref]$n) -and $n -ge 1 -and $n -le $script:AllAdapters.Count) { return $script:AllAdapters[$n - 1] }
    Write-Host (T 'adapter.invalid') -ForegroundColor Yellow
    return $def
}

function Invoke-AdapterCheck {
    $a = $script:Adapter
    $key = "$($a.Index)|$($a.IP)"
    if ($script:CheckedAdapter.ContainsKey($key)) { return }
    $script:CheckedAdapter[$key] = $true
    $cat = T 'cat.adapter'
    Write-Section (T 'sec.adapter' $a.Alias)

    Add-Result $cat (T 'res.adapter.config') 'INFO' (T 'res.adapter.config.d' $a.IP $a.Prefix $a.Mask $a.Network (Format-Value $a.Gateway) (Format-Value ($a.Dns -join ', ')) $a.Dhcp $a.Mac $a.LinkSpeed)

    # Wszystkie testy są wymuszone przez IPv4 (gniazda IPv4 związane z adresem karty, tylko rekordy A,
    # serwery DNS IPv4) - urządzenia SMA obsługują wyłącznie IPv4.
    $v6 = @($a.IPv6)
    if ($v6.Count -gt 0) {
        $v6Txt = ($v6 -join ', ')
        if ($a.IPv6Gateway) { $v6Txt += ' (' + (T 'word.gateway') + ' ' + $a.IPv6Gateway + ')' }
        Add-Result $cat (T 'res.ipv4only') 'INFO' (T 'res.ipv4only.v6.d' $a.IP $v6Txt) (T 'res.ipv4only.v6.h')
    } else {
        Add-Result $cat (T 'res.ipv4only') 'INFO' (T 'res.ipv4only.d' $a.IP)
    }

    if ($a.IP -like '169.254.*') {
        Add-Result $cat (T 'res.apipa') 'FAIL' (T 'res.apipa.d' $a.IP) (T 'res.apipa.h')
    }
    if ($a.Prefix -lt 16 -or $a.Prefix -gt 30) {
        Add-Result $cat (T 'res.mask') 'WARN' (T 'res.mask.d' $a.Prefix) (T 'res.mask.h')
    }
    if (-not $a.Gateway) {
        Add-Result $cat (T 'res.gw') 'WARN' (T 'res.gw.none.d') (T 'res.gw.none.h')
    } else {
        $p = Test-Ping $a.Gateway 1000 2
        if ($p) { Add-Result $cat (T 'res.gwping' $a.Gateway) 'OK' (T 'word.ms' $p) }
        else    { Add-Result $cat (T 'res.gwping' $a.Gateway) 'WARN' (T 'res.gwping.fail.d') (T 'res.gwping.fail.h') }
    }
    if (-not $a.Dns -or $a.Dns.Count -eq 0) {
        Add-Result $cat (T 'res.dns') 'WARN' (T 'res.dns.none.d') (T 'res.dns.none.h')
    }
    if ($a.Wireless) {
        Add-Result $cat (T 'res.wifi') 'WARN' (T 'res.wifi.d') (T 'res.wifi.h')
    }
    if ($a.Virtual) {
        Add-Result $cat (T 'res.virtual') 'WARN' $a.Description (T 'res.virtual.h')
    }
    $others = @($script:AllAdapters | Where-Object { $_.Index -ne $a.Index })
    $vpn = @($others | Where-Object { $_.Virtual -and $_.Gateway })
    if ($vpn.Count -gt 0) {
        Add-Result $cat (T 'res.vpn') 'WARN' (($vpn | ForEach-Object { $_.Alias }) -join ', ') (T 'res.vpn.h')
    }
    $overlap = @($others | Where-Object { (Test-InSubnet $_.IP $a.IP ([math]::Min($_.Prefix, $a.Prefix))) })
    if ($overlap.Count -gt 0) {
        Add-Result $cat (T 'res.overlap') 'WARN' (($overlap | ForEach-Object { "$($_.Alias) $($_.IP)" }) -join ', ') (T 'res.overlap.h')
    }
    $gwOthers = @($others | Where-Object { $_.Gateway -and -not $_.Virtual })
    if ($gwOthers.Count -gt 0) {
        Add-Result $cat (T 'res.multigw') 'INFO' (($gwOthers | ForEach-Object { "$($_.Alias) ($($_.IP))" }) -join ', ') (T 'res.multigw.h')
    }
    if ($a.Category -eq 'Public') {
        Add-Result $cat (T 'res.public') 'INFO' (T 'res.public.d' $a.Profile) (T 'res.public.h')
    }
}

# =====================================================================================
#  TESTY NISKOPOZIOMOWE
# =====================================================================================
function Test-Ping([string]$Ip, [int]$TimeoutMs = 1000, [int]$Count = 2) {
    # Tylko IPv4 - adres parsowany wprost, bez rozwiązywania nazw (brak ryzyka wyboru IPv6)
    if (-not (Test-IsIPv4 $Ip)) { return $null }
    $addr = [Net.IPAddress]::Parse($Ip)
    $p = New-Object Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $r = $p.Send($addr, $TimeoutMs)
                # zwracamy tekst, aby wynik "0" ms był traktowany jako sukces
                if ($r.Status -eq 'Success') { return [string]$r.RoundtripTime }
            } catch { }
        }
    } finally { $p.Dispose() }
    return $null
}

function Open-TcpSocket {
    param([string]$RemoteIp, [int]$Port, [string]$LocalIp, [int]$TimeoutMs = 4000)
    $sock = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($LocalIp) { $sock.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIp), 0))) }
        $ar = $sock.BeginConnect([Net.IPAddress]::Parse($RemoteIp), $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $sock.Close()
            return [pscustomobject]@{ Socket = $null; Error = 'TimedOut'; Ms = $sw.ElapsedMilliseconds }
        }
        $sock.EndConnect($ar)
        return [pscustomobject]@{ Socket = $sock; Error = $null; Ms = $sw.ElapsedMilliseconds }
    } catch {
        $sock.Close()
        return [pscustomobject]@{ Socket = $null; Error = (Get-SocketErrorText $_); Ms = $sw.ElapsedMilliseconds }
    }
}

function Test-TcpPort([string]$RemoteIp, [int]$Port, [string]$LocalIp, [int]$TimeoutMs = 4000) {
    $c = Open-TcpSocket -RemoteIp $RemoteIp -Port $Port -LocalIp $LocalIp -TimeoutMs $TimeoutMs
    if ($c.Socket) { $c.Socket.Close(); return [pscustomobject]@{ Ok = $true; Error = $null; Ms = $c.Ms } }
    return [pscustomobject]@{ Ok = $false; Error = $c.Error; Ms = $c.Ms }
}

function Test-TlsEndpoint([string]$RemoteIp, [string]$HostName, [int]$Port, [string]$LocalIp) {
    $res = [ordered]@{ TcpOk = $false; TcpError = $null; TcpMs = 0; TlsOk = $false; TlsError = $null
                       Issuer = ''; Subject = ''; NotAfter = $null; ChainErrors = ''; Inspection = $false; SmaCa = $false; Http = '' }
    $c = Open-TcpSocket -RemoteIp $RemoteIp -Port $Port -LocalIp $LocalIp
    $res.TcpMs = $c.Ms
    if (-not $c.Socket) { $res.TcpError = $c.Error; return [pscustomobject]$res }
    $res.TcpOk = $true
    $ssl = $null
    try {
        $ns = New-Object Net.Sockets.NetworkStream($c.Socket, $true)
        $ns.ReadTimeout = 6000; $ns.WriteTimeout = 6000
        $script:__tlsErrors = $null; $script:__tlsCert = $null
        $cb = [Net.Security.RemoteCertificateValidationCallback] {
            param($s, $cert, $chain, $errors)
            $script:__tlsErrors = $errors
            if ($cert) { $script:__tlsCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert) }
            return $true
        }
        $ssl = New-Object Net.Security.SslStream($ns, $false, $cb)
        $ssl.AuthenticateAsClient($HostName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $res.TlsOk = $true
        if ($script:__tlsCert) {
            $res.Issuer = $script:__tlsCert.Issuer; $res.Subject = $script:__tlsCert.Subject; $res.NotAfter = $script:__tlsCert.NotAfter
        }
        $res.ChainErrors = [string]$script:__tlsErrors
        # Część serwerów SMA (np. update.sunnyportal.de) używa prywatnego CA SMA - Windows mu nie ufa, urządzenia SMA tak.
        $res.SmaCa = ($res.Issuer -match 'Sunny Portal CA|O=SMA Solar Technology')
        if (-not $res.SmaCa -and (($res.ChainErrors -and $res.ChainErrors -ne 'None') -or $res.Issuer -match $script:SslInspectionPattern)) { $res.Inspection = $true }
        try {
            $req = [Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.1`r`nHost: $HostName`r`nUser-Agent: SMA-NetCheck/$($script:Version)`r`nConnection: close`r`n`r`n")
            $ssl.Write($req, 0, $req.Length); $ssl.Flush()
            $buf = New-Object byte[] 2048
            $n = $ssl.Read($buf, 0, $buf.Length)
            if ($n -gt 0) { $res.Http = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r?`n")[0] }
        } catch { $res.Http = (T 'tls.nohttp') }
    } catch {
        $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
        $res.TlsError = $ex.Message
    } finally {
        if ($ssl) { $ssl.Dispose() }
        $c.Socket.Close()
    }
    return [pscustomobject]$res
}

function Test-Ntp([string]$RemoteIp, [string]$LocalIp, [int]$TimeoutMs = 3000) {
    $u = $null
    try {
        $u = New-Object Net.Sockets.UdpClient((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIp), 0)))
        $u.Client.ReceiveTimeout = $TimeoutMs
        $pkt = New-Object byte[] 48; $pkt[0] = 0x1B
        $t0 = [DateTime]::UtcNow
        [void]$u.Send($pkt, 48, (New-Object Net.IPEndPoint([Net.IPAddress]::Parse($RemoteIp), 123)))
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep)
        $t1 = [DateTime]::UtcNow
        if ($r.Length -lt 48) { return [pscustomobject]@{ Ok = $false; Error = (T 'ntp.short'); OffsetSec = $null } }
        [byte[]]$sb = $r[40..43]; [Array]::Reverse($sb); $sec = [BitConverter]::ToUInt32($sb, 0)
        [byte[]]$fb = $r[44..47]; [Array]::Reverse($fb); $frac = [BitConverter]::ToUInt32($fb, 0)
        $server = (New-Object DateTime(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddSeconds([double]$sec + [double]$frac / 4294967296.0)
        $mid = $t0.AddTicks([long](($t1 - $t0).Ticks / 2))
        return [pscustomobject]@{ Ok = $true; Error = $null; OffsetSec = [math]::Round(($server - $mid).TotalSeconds, 2); Ms = [int]($t1 - $t0).TotalMilliseconds }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = (Get-SocketErrorText $_); OffsetSec = $null }
    } finally { if ($u) { $u.Close() } }
}

function Resolve-ARecord([string]$Name, [string]$Server) {
    try {
        $p = @{ Name = $Name; Type = 'A'; DnsOnly = $true; ErrorAction = 'Stop' }
        if ($Server) { $p.Server = $Server }
        $r = Resolve-DnsName @p
        $ips = @($r | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
        if ($ips.Count -gt 0) { return [pscustomobject]@{ Ok = $true; IPs = $ips; Error = $null } }
        return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'dns.noA') }
    } catch {
        return [pscustomobject]@{ Ok = $false; IPs = @(); Error = $_.Exception.Message }
    }
}

function Skip-DnsName([byte[]]$D, [ref]$Pos) {
    $p = $Pos.Value
    while ($p -lt $D.Length) {
        $len = $D[$p]
        if ($len -eq 0) { $p++; break }
        if (($len -band 0xC0) -eq 0xC0) { $p += 2; break }
        $p += $len + 1
    }
    $Pos.Value = $p
}

function Get-DnsAnswerA([byte[]]$D) {
    if ($D.Length -lt 12) { return @() }
    $qd = ($D[4] -shl 8) -bor $D[5]
    $total = (($D[6] -shl 8) -bor $D[7]) + (($D[8] -shl 8) -bor $D[9]) + (($D[10] -shl 8) -bor $D[11])
    $pos = 12
    for ($i = 0; $i -lt $qd; $i++) { Skip-DnsName $D ([ref]$pos); $pos += 4 }
    $ips = @()
    for ($i = 0; $i -lt $total -and $pos -lt $D.Length; $i++) {
        Skip-DnsName $D ([ref]$pos)
        if ($pos + 10 -gt $D.Length) { break }
        $type = ($D[$pos] -shl 8) -bor $D[$pos + 1]
        $rdlen = ($D[$pos + 8] -shl 8) -bor $D[$pos + 9]
        $pos += 10
        if ($type -eq 1 -and $rdlen -eq 4 -and $pos + 4 -le $D.Length) {
            $ips += ('{0}.{1}.{2}.{3}' -f $D[$pos], $D[$pos + 1], $D[$pos + 2], $D[$pos + 3])
        }
        $pos += $rdlen
    }
    return @($ips | Select-Object -Unique)
}

function Resolve-Mdns([string]$Name, [string]$LocalIp, [int]$TimeoutMs = 2000) {
    $n = $Name.TrimEnd('.')
    if ($n -notmatch '\.local$') { $n = ($n.Split('.')[0]) + '.local' }
    $q = New-Object System.Collections.Generic.List[byte]
    $q.AddRange([byte[]](0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in $n.Split('.')) {
        $b = [Text.Encoding]::ASCII.GetBytes($label)
        $q.Add([byte]$b.Length); $q.AddRange($b)
    }
    $q.AddRange([byte[]](0, 0, 1, 0x80, 1))   # typ A, klasa IN + bit QU (odpowiedź unicast)
    $u = $null
    try {
        $u = New-Object Net.Sockets.UdpClient((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIp), 0)))
        $u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastInterface, ([Net.IPAddress]::Parse($LocalIp)).GetAddressBytes())
        $bytes = $q.ToArray()
        [void]$u.Send($bytes, $bytes.Length, (New-Object Net.IPEndPoint([Net.IPAddress]::Parse('224.0.0.251'), 5353)))
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            if ($u.Client.Poll(200000, [Net.Sockets.SelectMode]::SelectRead)) {
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $data = $u.Receive([ref]$ep)
                $ips = @(Get-DnsAnswerA $data)
                if ($ips.Count -gt 0) { return [pscustomobject]@{ Ok = $true; IPs = $ips; Error = $null } }
            }
        }
        return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'mdns.noresp') }
    } catch {
        return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (Get-SocketErrorText $_) }
    } finally { if ($u) { $u.Close() } }
}

function Read-DnsNameAt([byte[]]$D, [ref]$Pos) {
    # Odczyt nazwy DNS z obsługą kompresji (wskaźniki 0xC0); przesuwa $Pos za nazwę
    $labels = New-Object System.Collections.Generic.List[string]
    $p = $Pos.Value; $jumped = $false; $guard = 0
    while ($p -lt $D.Length -and $guard -lt 100) {
        $guard++
        $len = [int]$D[$p]
        if ($len -eq 0) { $p++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($p + 1 -ge $D.Length) { break }
            if (-not $jumped) { $Pos.Value = $p + 2; $jumped = $true }
            $p = (($len -band 0x3F) -shl 8) -bor [int]$D[$p + 1]
            continue
        }
        if ($p + 1 + $len -gt $D.Length) { break }
        $labels.Add([Text.Encoding]::UTF8.GetString($D, $p + 1, $len))
        $p += $len + 1
    }
    if (-not $jumped) { $Pos.Value = $p }
    return ($labels -join '.')
}

function Get-DnsAnswerPtr([byte[]]$D) {
    # Zwraca rekordy PTR z odpowiedzi DNS/mDNS: @{ Owner = '50.10.168.192.in-addr.arpa'; Target = 'SMA123.local' }
    $out = @()
    if ($D.Length -lt 12) { return $out }
    $qd = ([int]$D[4] -shl 8) -bor $D[5]
    $total = (([int]$D[6] -shl 8) -bor $D[7]) + (([int]$D[8] -shl 8) -bor $D[9]) + (([int]$D[10] -shl 8) -bor $D[11])
    $pos = 12
    for ($i = 0; $i -lt $qd -and $pos -lt $D.Length; $i++) { [void](Read-DnsNameAt $D ([ref]$pos)); $pos += 4 }
    for ($i = 0; $i -lt $total -and $pos -lt $D.Length; $i++) {
        $owner = Read-DnsNameAt $D ([ref]$pos)
        if ($pos + 10 -gt $D.Length) { break }
        $type = ([int]$D[$pos] -shl 8) -bor $D[$pos + 1]
        $rdlen = ([int]$D[$pos + 8] -shl 8) -bor $D[$pos + 9]
        $pos += 10
        if ($type -eq 12 -and $pos + $rdlen -le $D.Length) {
            $rp = $pos
            $out += [pscustomobject]@{ Owner = $owner; Target = (Read-DnsNameAt $D ([ref]$rp)) }
        }
        $pos += $rdlen
    }
    return $out
}

function Resolve-MdnsReverseBatch([string[]]$Ips, [string]$LocalIp, [int]$TimeoutMs = 2500) {
    # Odwrotne zapytania mDNS (PTR x.x.x.x.in-addr.arpa) do wszystkich adresów naraz.
    # Urządzenia ogłaszające się przez mDNS (np. SMA ennexOS) podają tak swoją nazwę, nawet gdy router jej nie zna.
    $names = @{}
    if (-not $Ips -or $Ips.Count -eq 0) { return $names }
    $u = $null
    try {
        $u = New-Object Net.Sockets.UdpClient((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIp), 0)))
        $u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastInterface, ([Net.IPAddress]::Parse($LocalIp)).GetAddressBytes())
        $grp = New-Object Net.IPEndPoint([Net.IPAddress]::Parse('224.0.0.251'), 5353)
        foreach ($ip in $Ips) {
            $o = $ip.Split('.')
            $q = New-Object System.Collections.Generic.List[byte]
            $q.AddRange([byte[]](0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            foreach ($label in @($o[3], $o[2], $o[1], $o[0], 'in-addr', 'arpa')) {
                $b = [Text.Encoding]::ASCII.GetBytes($label); $q.Add([byte]$b.Length); $q.AddRange($b)
            }
            $q.AddRange([byte[]](0, 0, 12, 0x80, 1))   # typ PTR, klasa IN + bit QU (odpowiedź unicast)
            $bytes = $q.ToArray()
            try { [void]$u.Send($bytes, $bytes.Length, $grp) } catch { }
        }
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            if ($u.Client.Poll(200000, [Net.Sockets.SelectMode]::SelectRead)) {
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                try { $data = $u.Receive([ref]$ep) } catch { continue }
                foreach ($r in @(Get-DnsAnswerPtr $data)) {
                    if ($r.Owner -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$') {
                        $ip = "$($Matches[4]).$($Matches[3]).$($Matches[2]).$($Matches[1])"
                        if ($r.Target -and -not $names.ContainsKey($ip)) { $names[$ip] = ($r.Target -replace '\.local\.?$', '') }
                    }
                }
            }
        }
    } catch { } finally { if ($u) { $u.Close() } }
    return $names
}

function Resolve-HostNameBatch([string[]]$Ips, [int]$TimeoutMs = 6000) {
    # Odwrotne rozwiązywanie nazw (DNS PTR z routera, NetBIOS) równolegle dla wszystkich adresów
    $names = @{}
    $jobs = @()
    foreach ($ip in $Ips) {
        try { $jobs += [pscustomobject]@{ Ip = $ip; Task = [Net.Dns]::GetHostEntryAsync([Net.IPAddress]::Parse($ip)) } } catch { }
    }
    if ($jobs.Count -eq 0) { return $names }
    try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($jobs | ForEach-Object { $_.Task }), $TimeoutMs) } catch { }
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion') {
            $n = [string]$j.Task.Result.HostName
            if ($n -and $n -ne $j.Ip) { $names[$j.Ip] = $n }
        }
    }
    return $names
}

# Świeże zapytania ARP (iphlpapi ResolveIpNetEntry2) - działa bez uprawnień administratora.
# Pozwala sprawdzić, czy urządzenie jest teraz online, nawet gdy blokuje ping.
if (-not ('SmaNetCheck.Arp' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
namespace SmaNetCheck {
    public static class Arp {
        [DllImport("iphlpapi.dll")]
        static extern int ResolveIpNetEntry2(byte[] row, IntPtr sourceAddress);

        // Zwraca MAC (AA-BB-CC-DD-EE-FF), gdy urządzenie odpowiedziało na ARP, w przeciwnym razie null
        public static string Resolve(string ip, int ifIndex) {
            try {
                byte[] row = new byte[88];                    // MIB_IPNET_ROW2
                row[0] = 2;                                   // AF_INET
                Array.Copy(IPAddress.Parse(ip).GetAddressBytes(), 0, row, 4, 4);
                BitConverter.GetBytes(ifIndex).CopyTo(row, 28);
                if (ResolveIpNetEntry2(row, IntPtr.Zero) != 0) return null;
                if (BitConverter.ToInt32(row, 72) != 6) return null;
                return BitConverter.ToString(row, 40, 6);
            } catch { return null; }
        }

        public static string[] ResolveMany(string[] ips, int ifIndex) {
            string[] res = new string[ips.Length];
            Parallel.For(0, ips.Length, new ParallelOptions { MaxDegreeOfParallelism = 32 }, i => { res[i] = Resolve(ips[i], ifIndex); });
            return res;
        }
    }
}
'@
}

function Get-LocalIPv4 {
    # Wszystkie adresy IPv4 tego komputera - także kart rozłączonych, które zachowały stary adres
    @(@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }) +
      @($script:AllAdapters | ForEach-Object { $_.IP }) | Where-Object { $_ } | Select-Object -Unique)
}

function Get-SubnetNeighbors($Adapter) {
    # Wpisy z tablicy ARP Windows z poprawnym MAC, w podsieci karty
    @(Get-NetNeighbor -InterfaceIndex $Adapter.Index -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and
                       $_.LinkLayerAddress -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF' -and
                       (Test-IsIPv4 $_.IPAddress) -and (Test-InSubnet $_.IPAddress $Adapter.IP $Adapter.Prefix) })
}

function Resolve-NetBios([string]$Name) {
    try {
        $r = Resolve-DnsName -Name ($Name.Split('.')[0]) -Type A -LlmnrNetbiosOnly -ErrorAction Stop
        $ips = @($r | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
        if ($ips.Count -gt 0) { return [pscustomobject]@{ Ok = $true; IPs = $ips; Error = $null } }
        return [pscustomobject]@{ Ok = $false; IPs = @(); Error = (T 'nb.noresp') }
    } catch { return [pscustomobject]@{ Ok = $false; IPs = @(); Error = $_.Exception.Message } }
}

function Get-ArpEntry([string]$Ip) {
    $n = Get-NetNeighbor -IPAddress $Ip -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
        Select-Object -First 1
    if ($n) { return $n.LinkLayerAddress }
    return $null
}

# =====================================================================================
#  SPEEDWIRE / MULTICAST
# =====================================================================================
$script:SpeedwireDiscovery = [byte[]](0x53, 0x4D, 0x41, 0x00, 0x00, 0x04, 0x02, 0xA0, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00)

function New-SpeedwireSocket([string]$LocalIp) {
    $s = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
    try {
        $s.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket, [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $s.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, $script:SpeedwirePort)))
        $mo = New-Object Net.Sockets.MulticastOption([Net.IPAddress]::Parse($script:SpeedwireGroup), [Net.IPAddress]::Parse($LocalIp))
        $s.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::AddMembership, [object]$mo)
        $s.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastInterface, ([Net.IPAddress]::Parse($LocalIp)).GetAddressBytes())
        $s.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastLoopback, $false)
        return $s
    } catch {
        $s.Close()
        throw
    }
}

function Get-SpeedwireInfo([byte[]]$D, [int]$N) {
    if ($N -lt 4 -or $D[0] -ne 0x53 -or $D[1] -ne 0x4D -or $D[2] -ne 0x41 -or $D[3] -ne 0) { return $null }
    $info = [ordered]@{ Kind = 'Speedwire'; Protocol = ''; SusyId = $null; Serial = $null; Model = (T 'model.speedwire') }
    if ($N -eq 20 -and $D[8] -eq 0xFF -and $D[9] -eq 0xFF -and $D[10] -eq 0xFF -and $D[11] -eq 0xFF) {
        $info.Kind = 'DiscoveryRequest'; $info.Model = (T 'model.discReq')
        return [pscustomobject]$info
    }
    if ($N -ge 18 -and $D[14] -eq 0x00 -and $D[15] -eq 0x10) {
        $proto = ($D[16] -shl 8) -bor $D[17]
        $info.Protocol = ('0x{0:X4}' -f $proto)
        if ($proto -eq 0x6069 -and $N -ge 24) {
            $info.Kind = 'EnergyMeter'
            $susy = ($D[18] -shl 8) -bor $D[19]
            [byte[]]$sb = $D[20..23]; [Array]::Reverse($sb)
            $info.SusyId = $susy; $info.Serial = [BitConverter]::ToUInt32($sb, 0)
            $info.Model = switch ($susy) {
                270     { T 'model.em' }
                349     { T 'model.em2' }
                372     { T 'model.shm2' }
                default { T 'model.meterSusy' $susy }
            }
        } elseif ($proto -eq 0x6065 -and $N -ge 34) {
            $info.Kind = 'SpeedwireData'
            $info.SusyId = $D[28] -bor ($D[29] -shl 8)
            $info.Serial = [BitConverter]::ToUInt32($D, 30)
            $info.Model = T 'model.data' $info.SusyId
        }
    } else {
        $info.Kind = 'DiscoveryResponse'; $info.Model = (T 'model.discResp')
    }
    return [pscustomobject]$info
}

function Receive-Speedwire {
    # Nasłuch na gnieździe Speedwire; zwraca listę pakietów {Time, IP, Info}
    param($Socket, [int]$Seconds, [string]$OnlyFromIp, [switch]$StopOnFirst, [switch]$Progress, [scriptblock]$OnTick)
    $packets = New-Object System.Collections.Generic.List[object]
    $buf = New-Object byte[] 2048
    $start = Get-Date
    $deadline = $start.AddSeconds($Seconds)
    $lastTick = -1
    while ((Get-Date) -lt $deadline) {
        $elapsed = [int]((Get-Date) - $start).TotalSeconds
        if ($elapsed -ne $lastTick) {
            $lastTick = $elapsed
            if ($Progress) {
                $pct = [math]::Min(100, [int](100 * $elapsed / [math]::Max(1, $Seconds)))
                $st = T 'status.mcListen' $elapsed $Seconds $packets.Count
                Write-Progress -Activity 'Speedwire 239.12.255.254:9522' -Status $st -PercentComplete $pct
                Set-NcStatus $st $pct
            }
            if ($OnTick) { & $OnTick $elapsed }
        }
        if ($Socket.Poll(200000, [Net.Sockets.SelectMode]::SelectRead)) {
            $ep = [Net.EndPoint](New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0))
            try { $n = $Socket.ReceiveFrom($buf, [ref]$ep) } catch { continue }
            $ip = ([Net.IPEndPoint]$ep).Address.ToString()
            if ($ip -eq $script:Adapter.IP) { continue }
            if ($OnlyFromIp -and $ip -ne $OnlyFromIp) { continue }
            $info = Get-SpeedwireInfo $buf $n
            if (-not $info) { continue }
            $packets.Add([pscustomobject]@{ Time = (Get-Date); IP = $ip; Info = $info })
            if ($StopOnFirst) { break }
        }
    }
    if ($Progress) { Write-Progress -Activity 'Speedwire' -Completed }
    return , $packets
}

function Clear-LeftoverFirewallRule {
    # Reguła pozostawiona po przerwanym teście (np. program zamknięty w Menedżerze zadań, wyłączenie komputera).
    # Usuwana przy starcie programu i przed testem multicast - tylko jako administrator. Zwraca $true, gdy usunięto.
    if (-not $script:IsAdmin -or $script:TempRuleAdded) { return $false }
    try {
        if (Get-NetFirewallRule -Name $script:TempRuleName -ErrorAction Stop) {
            Remove-NetFirewallRule -Name $script:TempRuleName -ErrorAction Stop
            Write-Host (T 'fw.leftover') -ForegroundColor DarkGray
            return $true
        }
    } catch { }
    return $false
}

function Test-FirewallForMulticast {
    $cat = T 'cat.multicast'
    $name = T 'res.fw'
    if (Clear-LeftoverFirewallRule) { Add-Result $cat (T 'res.fw.leftover') 'INFO' (T 'fw.leftover') }
    $profName = switch ($script:Adapter.Category) { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } }
    $fp = $null
    try { $fp = Get-NetFirewallProfile -Name $profName -ErrorAction Stop } catch { }
    if (-not $fp) {
        Add-Result $cat $name 'INFO' (T 'res.fw.unknown.d') (T 'res.fw.unknown.h')
        return
    }
    if ("$($fp.Enabled)" -ne 'True') {
        Add-Result $cat $name 'OK' (T 'res.fw.off.d' $profName)
        return
    }
    if ($script:TempRuleAdded) {
        Add-Result $cat $name 'OK' (T 'res.fw.temprule.d' $profName)
        return
    }
    $hint = T 'res.fw.h'
    if ($script:IsAdmin) {
        $add = $AddFirewallRule
        if (-not $add -and $script:Interactive) {
            $ans = Read-Host (T 'prompt.fwrule')
            $add = ($ans -eq '' -or $ans -match $script:YesPattern)
        }
        if ($add) {
            try {
                # Reguła możliwie wąska: tylko ten program (powershell.exe, w którym działa test), tylko bieżący profil sieci
                $exe = (Get-Process -Id $PID).Path
                New-NetFirewallRule -Name $script:TempRuleName -DisplayName (T 'fw.rulename') -Description (T 'fw.ruledesc') `
                    -Direction Inbound -Protocol UDP -LocalPort 9522, 5353 -Program $exe -Profile $profName -Action Allow -ErrorAction Stop | Out-Null
                $script:TempRuleAdded = $true
                Add-Result $cat $name 'OK' (T 'res.fw.added.d')
                return
            } catch {
                Add-Result $cat $name 'WARN' (T 'res.fw.addfail.d' $_.Exception.Message) $hint
                return
            }
        }
        Add-Result $cat $name 'WARN' (T 'res.fw.norule.d' $profName) $hint
    } else {
        Add-Result $cat $name 'WARN' (T 'res.fw.noadmin.d' $profName) ($hint + "`n" + (T 'res.fw.noadmin.h'))
    }
}

function Remove-TempFirewallRule {
    if ($script:TempRuleAdded) {
        try { Remove-NetFirewallRule -Name $script:TempRuleName -ErrorAction Stop; $script:TempRuleAdded = $false; Write-Host (T 'fw.removed') -ForegroundColor DarkGray }
        catch { Write-Host (T 'fw.removefail' $script:TempRuleName) -ForegroundColor Yellow }
    }
}

# =====================================================================================
#  TEST 1: PORTAL / INTERNET
# =====================================================================================
function Invoke-PortalTest {
    $a = $script:Adapter
    Invoke-AdapterCheck
    Write-Section (T 'sec.portal')
    $cat = T 'cat.portal'
    Write-Host (T 'portal.src' $a.IP $a.Alias) -ForegroundColor DarkGray
    Write-Host (T 'portal.note') -ForegroundColor DarkGray

    # --- Proxy ---
    Write-Sub (T 'sub.proxy')
    $proxyInfo = @()
    try {
        $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) { $proxyInfo += (T 'proxy.user' $ie.ProxyServer) }
        if ($ie.AutoConfigURL) { $proxyInfo += (T 'proxy.pac' $ie.AutoConfigURL) }
    } catch { }
    $wh = (netsh winhttp show proxy) -join ' '
    if ($wh -match 'Proxy Server\(s\)\s*:\s*(\S+)' -or $wh -match 'Serwer\(y\) proxy\s*:\s*(\S+)' -or $wh -match 'Proxyserver\s*:\s*(\S+)') { $proxyInfo += (T 'proxy.winhttp' $Matches[1]) }
    if ($proxyInfo.Count -gt 0) {
        Add-Result $cat (T 'res.proxy') 'WARN' ($proxyInfo -join '; ') (T 'res.proxy.h')
    } else {
        Add-Result $cat (T 'res.proxy') 'OK' (T 'res.proxy.none')
    }

    # --- DNS ---
    Write-Sub (T 'sub.dns')
    $dnsServers = @($a.Dns)
    $workingDns = @()
    foreach ($s in $dnsServers) {
        $r = Resolve-ARecord $script:DnsTestName $s
        if ($r.Ok) { $workingDns += $s; Add-Result $cat (T 'res.dnsLocal' $s) 'OK' (T 'word.responds') }
        else { Add-Result $cat (T 'res.dnsLocal' $s) 'FAIL' $r.Error (T 'res.dnsLocal.h') }
    }
    $publicOk = @()
    foreach ($s in $script:PublicDns) {
        $r = Resolve-ARecord $script:DnsTestName $s
        if ($r.Ok) { $publicOk += $s; Add-Result $cat (T 'res.dnsPublic' $s) 'OK' (T 'word.reachable') }
        else { Add-Result $cat (T 'res.dnsPublic' $s) 'WARN' $r.Error (T 'res.dnsPublic.h') }
    }

    # --- Cele ---
    Write-Sub (T 'sub.targets')
    $smaFail = 0; $smaTotal = 0; $ctrlFail = 0
    foreach ($t in @($script:PortalTargets) + @($script:ControlTargets)) {
        $isCtrl = [bool]$t.Control
        $label = "$(T $t.Key) [$($t.HostName):$($t.Port)]"
        $for = T $t.ForKey
        $ips = @()
        if (Test-IsIPv4 $t.HostName) { $ips = @($t.HostName) }
        else {
            $r = $null
            if ($workingDns.Count -gt 0) { $r = Resolve-ARecord $t.HostName $workingDns[0] }
            if (-not $r -or -not $r.Ok) {
                $pub = $null
                foreach ($s in $publicOk) { $pub = Resolve-ARecord $t.HostName $s; if ($pub.Ok) { break } }
                if ($pub -and $pub.Ok) {
                    $ips = $pub.IPs
                    if ($workingDns.Count -gt 0) {
                        Add-Result $cat (T 'res.dnsName' $t.HostName) 'WARN' (T 'res.dnsName.localfail.d' $r.Error ($ips -join ', ')) (T 'res.dnsName.localfail.h')
                    }
                } else {
                    Add-Result $cat (T 'res.dnsName' $t.HostName) 'FAIL' (T 'res.dnsName.fail.d') (T 'res.dnsName.fail.h')
                    if (-not $isCtrl) { $smaFail++; $smaTotal++ } else { $ctrlFail++ }
                    continue
                }
            } else { $ips = $r.IPs }
            $bad = @($ips | Where-Object { Test-IsPrivateIp $_ })
            if ($bad.Count -gt 0) {
                Add-Result $cat (T 'res.dnsName' $t.HostName) 'WARN' (T 'res.dnsName.private.d' ($bad -join ', ')) (T 'res.dnsName.private.h')
            }
        }
        $ip = $ips[0]
        if (-not $isCtrl) { $smaTotal++ }
        $unblock = T 'res.unblock.h' $t.Port $t.HostName $ip $for

        switch ($t.Type) {
            'TLS' {
                $res = Test-TlsEndpoint -RemoteIp $ip -HostName $t.HostName -Port $t.Port -LocalIp $a.IP
                if (-not $res.TcpOk) {
                    Add-Result $cat $label 'FAIL' (T 'res.tcpfail.d' $ip (Get-TcpErrorText $res.TcpError)) $unblock
                    if ($isCtrl) { $ctrlFail++ } else { $smaFail++ }
                } elseif (-not $res.TlsOk) {
                    Add-Result $cat $label 'FAIL' (T 'res.tlsfail.d' $ip $res.TcpMs $res.TlsError) (T 'res.tlsfail.h')
                    if ($isCtrl) { $ctrlFail++ } else { $smaFail++ }
                } elseif ($res.Inspection) {
                    Add-Result $cat $label 'WARN' (T 'res.inspect.d' $ip $res.Issuer $res.ChainErrors) (T 'res.inspect.h')
                    if (-not $isCtrl) { $smaFail++ }
                } else {
                    $caNote = if ($res.SmaCa) { T 'res.smaca' } else { '' }
                    Add-Result $cat $label 'OK' (T 'res.tlsok.d' $ip $res.TcpMs $caNote $res.Http)
                }
            }
            'TCP' {
                $res = Test-TcpPort -RemoteIp $ip -Port $t.Port -LocalIp $a.IP
                if ($res.Ok) { Add-Result $cat $label 'OK' (T 'res.tcpok.d' $ip $res.Ms) }
                else {
                    $h = $unblock
                    if ($t.Port -eq 9524) { $h += "`n" + (T 'res.9524.h') }
                    Add-Result $cat $label 'FAIL' "$ip - $(Get-TcpErrorText $res.Error)" $h
                    if ($isCtrl) { $ctrlFail++ } else { $smaFail++ }
                }
            }
            'NTP' {
                $res = Test-Ntp -RemoteIp $ip -LocalIp $a.IP
                if ($res.Ok) {
                    Add-Result $cat $label 'OK' (T 'res.ntpok.d' $ip $res.Ms $res.OffsetSec)
                    if ([math]::Abs($res.OffsetSec) -gt 120) {
                        Add-Result $cat (T 'res.clock') 'WARN' (T 'res.clock.d' $res.OffsetSec) (T 'res.clock.h')
                    }
                } else {
                    Add-Result $cat $label 'WARN' (T 'res.ntpfail.d' $ip $res.Error) (T 'res.ntpfail.h' $t.HostName)
                    if (-not $isCtrl) { $smaFail++ }
                }
            }
        }
    }

    # --- Diagnoza zbiorcza ---
    Write-Sub (T 'sub.diag')
    if ($ctrlFail -ge 2 -and $smaFail -ge 1) {
        Add-Result $cat (T 'res.diag') 'FAIL' (T 'res.diag.noinet.d') (T 'res.diag.noinet.h')
    } elseif ($smaFail -gt 0) {
        Add-Result $cat (T 'res.diag') 'FAIL' (T 'res.diag.sma.d' $smaFail $smaTotal) ((T 'res.diag.sma.h') + "`n" + (T 'res.status.fail.h' $script:StatusPageUrl))
    } else {
        Add-Result $cat (T 'res.diag') 'OK' (T 'res.diag.ok.d') (T 'res.diag.ok.h')
    }
    Add-Result $cat (T 'res.status') 'INFO' $script:StatusPageUrl (T 'res.status.h')
}

# =====================================================================================
#  TEST 2: URZĄDZENIA W SIECI LOKALNEJ
# =====================================================================================
function Get-SecondaryIpHint([string]$DeviceIp) {
    $parts = $DeviceIp.Split('.')
    $sugg = "$($parts[0]).$($parts[1]).$($parts[2]).250"
    if ($sugg -eq $DeviceIp) { $sugg = "$($parts[0]).$($parts[1]).$($parts[2]).251" }
    return (T 'hint.secondaryIp' $script:Adapter.Alias $sugg)
}

function Test-LocalDevice([string]$Target) {
    $a = $script:Adapter
    $cat = T 'cat.device' $Target
    Write-Sub $cat

    # --- Rozwiązywanie nazwy ---
    $found = @{}   # ip -> lista metod
    $isIp = Test-IsIPv4 $Target
    $base = $Target -replace '\.local\.?$', ''      # SMA782354782.local -> SMA782354782
    $rDns = $null; $rMdns = $null; $rNb = $null
    if ($isIp) {
        $found[$Target] = @(T 'src.ip')
    } else {
        # DNS: zapytanie o rekord A wysyłane do serwera DNS IPv4 z wybranej karty (nie do DNS IPv6)
        $dns4 = @($a.Dns | Where-Object { Test-IsIPv4 $_ }) | Select-Object -First 1
        $rDns  = Resolve-ARecord $base $dns4
        $rMdns = Resolve-Mdns $base $a.IP
        $rNb   = Resolve-NetBios $base
        $methods = @(, @('DNS', $rDns)) + @(, @('mDNS (.local)', $rMdns)) + @(, @('NetBIOS/LLMNR', $rNb))
        foreach ($m in $methods) {
            $name = $m[0]; $res = $m[1]
            if ($res.Ok) {
                foreach ($ip in $res.IPs) { if (-not $found.ContainsKey($ip)) { $found[$ip] = @() }; $found[$ip] += $name }
                Add-Result $cat (T 'res.resolve' $name) 'OK' ($res.IPs -join ', ')
            } else {
                Add-Result $cat (T 'res.resolve' $name) 'INFO' (T 'res.resolve.none.d' $res.Error)
            }
        }
        if ($found.Count -eq 0) {
            Add-Result $cat (T 'res.resolve.all') 'FAIL' (T 'res.resolve.fail.d' $Target) (T 'res.resolve.fail.h')
            return
        }
        if ($found.Count -gt 1) {
            Add-Result $cat (T 'res.inconsistent') 'WARN' (($found.Keys | ForEach-Object { "$_ ($($found[$_] -join '/'))" }) -join '; ') (T 'res.inconsistent.h')
        }
    }

    $web = @{}   # ip -> wynik testu HTTPS (interfejs WWW)
    foreach ($ip in @($found.Keys)) {
        $addrName = T 'res.addr' $ip
        if ((Get-LocalIPv4) -contains $ip) {
            Add-Result $cat $addrName 'WARN' (T 'res.self.d') (T 'res.self.h')
            continue
        }
        $inSub = Test-InSubnet $ip $a.IP $a.Prefix
        $ping = Test-Ping $ip 1000 2
        $mac = if ($inSub) { Get-ArpEntry $ip } else { $null }
        $vendor = Get-MacVendor $mac
        $isSma = [bool]$vendor

        if ($ip -like '169.254.*') {
            Add-Result $cat $addrName 'FAIL' (T 'res.dev.apipa.d') ((T 'res.dev.apipa.h') + "`n" + (Get-SecondaryIpHint $ip))
        } elseif (-not $inSub) {
            if ($ping) {
                Add-Result $cat $addrName 'WARN' (T 'res.dev.outside.ping.d' $a.Network $a.Prefix $ping) (T 'res.dev.outside.ping.h')
            } else {
                Add-Result $cat $addrName 'FAIL' (T 'res.dev.outside.d' $a.Network $a.Prefix) ((T 'res.dev.outside.h' $a.Network $a.Prefix) + "`n" + (Get-SecondaryIpHint $ip))
            }
        } else {
            if ($ping -and $mac) {
                $smaFlag = if ($isSma) { " ($vendor)" } else { '' }
                Add-Result $cat $addrName 'OK' (T 'res.dev.ok.mac.d' $ping $mac $smaFlag)
            } elseif ($ping) {
                Add-Result $cat $addrName 'OK' (T 'res.dev.ok.d' $ping)
            } elseif ($mac) {
                Add-Result $cat $addrName 'WARN' (T 'res.dev.arponly.d' $mac) (T 'res.dev.arponly.h')
            } else {
                Add-Result $cat $addrName 'FAIL' (T 'res.dev.none.d') (T 'res.dev.none.h')
            }
            if ($mac -and -not $isSma) {
                Add-Result $cat (T 'res.vendor' $ip) 'WARN' (T 'res.vendor.d' $mac (Get-VendorOuiText)) (T 'res.vendor.h')
            }
        }

        if (-not $ping -and -not $mac -and -not $inSub) { continue }

        # --- Porty TCP ---
        $open = @()
        $err443 = $null
        foreach ($p in $script:LocalTcpPorts) {
            $pName = T 'res.port' $p.Port (T $p.Key) $ip
            $t = Test-TcpPort -RemoteIp $ip -Port $p.Port -LocalIp $a.IP -TimeoutMs 2000
            if ($t.Ok) { $open += $p.Port; Add-Result $cat $pName 'OK' (T 'res.port.open.d' $t.Ms) }
            else {
                if ($p.Port -eq 443) { $err443 = $t.Error }
                Add-Result $cat $pName 'INFO' (Get-TcpErrorText $t.Error)
            }
        }

        # --- HTTPS (interfejs WWW): handshake TLS + odpowiedź HTTP; certyfikat urządzenia jest samopodpisany ---
        if ($open -contains 443) {
            $tls = Test-TlsEndpoint -RemoteIp $ip -HostName $base -Port 443 -LocalIp $a.IP
            $web[$ip] = [pscustomobject]@{ Ok = $tls.TlsOk; Http = $tls.Http; Error = $(if ($tls.TlsOk) { $null } elseif ($tls.TcpError) { Get-TcpErrorText $tls.TcpError } else { T 'res.webui.tlserr' $tls.TlsError }) }
        } else {
            $web[$ip] = [pscustomobject]@{ Ok = $false; Http = ''; Error = (T 'res.webui.closed' (Get-TcpErrorText $err443)) }
        }

        # --- Speedwire unicast ---
        $swName = T 'res.sw' $ip
        $sock = $null
        try {
            $sock = New-SpeedwireSocket $a.IP
            [void]$sock.SendTo($script:SpeedwireDiscovery, (New-Object Net.IPEndPoint([Net.IPAddress]::Parse($ip), $script:SpeedwirePort)))
            $pk = Receive-Speedwire -Socket $sock -Seconds 2 -OnlyFromIp $ip -StopOnFirst
            if ($pk.Count -gt 0) {
                Add-Result $cat $swName 'OK' (T 'res.sw.ok.d' $pk[0].Info.Model)
            } else {
                Add-Result $cat $swName 'INFO' (T 'res.sw.none.d') (T 'res.sw.none.h')
            }
        } catch {
            Add-Result $cat $swName 'INFO' (T 'res.sw.err.d' (Get-SocketErrorText $_)) (T 'res.sw.err.h')
        } finally { if ($sock) { $sock.Close() } }
    }

    # --- Interfejs WWW: pod jakimi adresami da się go otworzyć w przeglądarce ---
    # https://<IP>, https://<hostname> (DNS / NetBIOS / LLMNR) oraz https://<hostname>.local (mDNS)
    $urls = @()
    foreach ($ip in @($found.Keys | Sort-Object { ConvertTo-UInt32 $_ })) {
        $urls += [pscustomobject]@{ Url = "https://$ip"; IPs = @($ip); Hint = '' }
    }
    if (-not $isIp) {
        $hostIps = @(@($(if ($rDns.Ok) { $rDns.IPs })) + @($(if ($rNb.Ok) { $rNb.IPs })) | Where-Object { $_ } | Select-Object -Unique)
        $urls += [pscustomobject]@{ Url = "https://$base"; IPs = $hostIps; Hint = (T 'res.webui.host.h' $base) }
        $urls += [pscustomobject]@{ Url = "https://$base.local"; IPs = @($(if ($rMdns.Ok) { $rMdns.IPs })); Hint = (T 'res.webui.local.h' $base) }
    }
    $working = @()
    foreach ($u in $urls) {
        $wName = T 'res.webui' $u.Url
        if ($u.IPs.Count -eq 0) {
            Add-Result $cat $wName 'WARN' (T 'res.webui.nores.d') $u.Hint
            continue
        }
        $okIp = $u.IPs | Where-Object { $web[$_] -and $web[$_].Ok } | Select-Object -First 1
        if ($okIp) {
            $working += $u.Url
            Add-Result $cat $wName 'OK' (T 'res.webui.ok.d' $okIp $web[$okIp].Http)
        } else {
            $ip0 = $u.IPs[0]
            $why = if ($web[$ip0]) { $web[$ip0].Error } else { T 'res.webui.unreach' }
            Add-Result $cat $wName 'WARN' "$ip0 - $why" (T 'res.web.h')
        }
    }
    if ($working.Count -gt 0) {
        Add-Result $cat (T 'res.webui.sum') 'OK' ($working -join '   ') (T 'res.webui.sum.h')
    } else {
        Add-Result $cat (T 'res.webui.sum') 'FAIL' (T 'res.webui.sum.none.d') (T 'res.webui.sum.none.h')
    }
}

function Invoke-LocalTest([string[]]$Targets) {
    Invoke-AdapterCheck
    Write-Section (T 'sec.local')
    if (-not $Targets -or $Targets.Count -eq 0) {
        $in = Read-Host (T 'prompt.devices')
        $Targets = @($in)
    }
    $Targets = @($Targets | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
    if ($Targets.Count -eq 0) { Write-Host (T 'local.none') -ForegroundColor Yellow; return }
    foreach ($t in $Targets) {
        # Akceptuje też wklejony adres z przeglądarki: https://SMA782354782.local/ -> SMA782354782.local
        $t = (($t.Trim() -replace '^[a-zA-Z]+://', '').Split('/')[0]) -replace ':\d+$', ''
        # Sam numer seryjny (same cyfry) -> hostname SMA + numer seryjny, np. 782354782 -> SMA782354782
        if ($t -match '^\d{6,}$') { $t = "SMA$t" }
        if ($t) { Test-LocalDevice $t }
    }
}

# =====================================================================================
#  TEST 3: SKANOWANIE PODSIECI
# =====================================================================================
function Invoke-SubnetScan([string]$Range) {
    # $Range = własny zakres IP (opcjonalnie); puste = automatycznie podsieć wybranej karty
    $a = $script:Adapter
    Invoke-AdapterCheck
    Write-Section (T 'sec.scan')
    $cat = T 'cat.scan'
    $rangeSet = $null
    if ($Range -and $Range.Trim()) {
        $r = Get-IpRangeList $Range
        if (-not $r.Ok) {
            Add-Result $cat (T 'res.range') 'FAIL' $r.Error (T 'range.examples')
            return
        }
        $label = ($Range.Trim() -split '[,;\s]+' | Where-Object { $_ }) -join ', '
        $hosts = @($r.IPs | Where-Object { $_ -ne $a.IP })
        $rangeSet = @{}; foreach ($ip in $r.IPs) { $rangeSet[$ip] = $true }
        Add-Result $cat (T 'res.range') 'INFO' (T 'res.range.d' $label $r.IPs.Count)
    } else {
        $prefix = $a.Prefix
        if ($prefix -lt 22) {
            Write-Host (T 'scan.big' $prefix) -ForegroundColor Yellow
            $prefix = 24
        }
        $netStr = Get-NetworkAddress $a.IP $prefix
        $net = ConvertTo-UInt32 $netStr
        $count = [math]::Pow(2, 32 - $prefix) - 2
        $hosts = for ($i = 1; $i -le $count; $i++) { ConvertFrom-UInt32 ([uint32]($net + $i)) }
        $hosts = @($hosts | Where-Object { $_ -ne $a.IP })
        $label = "$netStr/$prefix"
    }
    # Urządzenia zapamiętane wcześniej przez Windows (pamięć ARP) - pozwala pokazać też te, które są teraz offline
    $known = @{}
    foreach ($n in (Get-SubnetNeighbors $a)) { $known[$n.IPAddress] = $n.LinkLayerAddress }
    $alive = @{}
    $batch = 128
    for ($i = 0; $i -lt $hosts.Count; $i += $batch) {
        $st = T 'status.scan' $label $i $hosts.Count
        Write-Progress -Activity 'Ping sweep' -Status $st -PercentComplete ([int](100 * $i / $hosts.Count))
        Set-NcStatus $st ([int](100 * $i / $hosts.Count))
        $chunk = $hosts[$i..([math]::Min($i + $batch, $hosts.Count) - 1)]
        $jobs = @()
        foreach ($h in $chunk) {
            $p = New-Object Net.NetworkInformation.Ping
            $jobs += [pscustomobject]@{ Ip = $h; Ping = $p; Task = $p.SendPingAsync($h, 800) }
        }
        try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($jobs | ForEach-Object { $_.Task }), 5000) } catch { }
        foreach ($j in $jobs) {
            if ($j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.Status -eq 'Success') { $alive[$j.Ip] = [int]$j.Task.Result.RoundtripTime }
            $j.Ping.Dispose()
        }
    }
    Write-Progress -Activity 'Ping sweep' -Completed
    Add-Result $cat (T 'res.sweep') 'INFO' (T 'res.sweep.d' $alive.Count $label)

    # Speedwire discovery (multicast) - łapie też urządzenia z adresem spoza podsieci
    $sw = @{}
    $sock = $null
    try {
        $sock = New-SpeedwireSocket $a.IP
        $grp = New-Object Net.IPEndPoint([Net.IPAddress]::Parse($script:SpeedwireGroup), $script:SpeedwirePort)
        [void]$sock.SendTo($script:SpeedwireDiscovery, $grp)
        Start-Sleep -Milliseconds 300
        [void]$sock.SendTo($script:SpeedwireDiscovery, $grp)
        foreach ($pk in (Receive-Speedwire -Socket $sock -Seconds 4)) {
            if ($pk.Info.Kind -eq 'DiscoveryRequest') { continue }
            if (-not $sw.ContainsKey($pk.IP)) { $sw[$pk.IP] = $pk.Info.Model }
        }
    } catch {
        Add-Result $cat (T 'res.swdisc') 'INFO' (T 'res.swdisc.err.d' (Get-SocketErrorText $_)) (T 'res.swdisc.err.h')
    } finally { if ($sock) { $sock.Close() } }

    # --- Wszystkie urządzenia: tablica ARP (przed i po ping sweep) + odpowiedzi ping + Speedwire ---
    $own = Get-LocalIPv4
    $all = @{}   # ip -> dane urządzenia
    foreach ($n in (Get-SubnetNeighbors $a)) { $all[$n.IPAddress] = [ordered]@{ IP = $n.IPAddress; MAC = $n.LinkLayerAddress } }
    foreach ($ip in $known.Keys) {
        if (-not $all.ContainsKey($ip)) { $all[$ip] = [ordered]@{ IP = $ip; MAC = $known[$ip] } }
    }
    foreach ($ip in @($alive.Keys) + @($sw.Keys)) {
        if (-not $all.ContainsKey($ip)) { $all[$ip] = [ordered]@{ IP = $ip; MAC = (Get-ArpEntry $ip) } }
    }
    foreach ($ip in $own) { $all.Remove($ip) }
    # Własny zakres: tylko adresy z zakresu (oraz urządzenia, które odpowiedziały na Speedwire)
    if ($rangeSet) {
        foreach ($ip in @($all.Keys)) { if (-not $rangeSet.ContainsKey($ip) -and -not $sw.ContainsKey($ip)) { $all.Remove($ip) } }
    }

    # --- Online / offline: odpowiedź na ping, Speedwire albo świeże zapytanie ARP (gdy ping jest blokowany) ---
    Set-NcStatus (T 'status.online' $all.Count)
    Write-Host (T 'status.online' $all.Count) -ForegroundColor DarkGray
    $toArp = @($all.Keys | Where-Object { -not $alive.ContainsKey($_) -and -not $sw.ContainsKey($_) -and (Test-InSubnet $_ $a.IP $a.Prefix) })
    $arpOk = @{}
    if ($toArp.Count -gt 0) {
        $macs = [SmaNetCheck.Arp]::ResolveMany([string[]]$toArp, [int]$a.Index)
        for ($i = 0; $i -lt $toArp.Count; $i++) { if ($macs[$i]) { $arpOk[$toArp[$i]] = $macs[$i] } }
    }
    foreach ($d in $all.Values) {
        $d.Online = ($alive.ContainsKey($d.IP) -or $sw.ContainsKey($d.IP) -or $arpOk.ContainsKey($d.IP))
        if ($arpOk[$d.IP]) { $d.MAC = $arpOk[$d.IP] }
    }
    # Urządzenie offline, którego MAC jest teraz online pod innym adresem = zmiana adresu IP
    $onlineByMac = @{}
    foreach ($d in $all.Values) { if ($d.Online -and $d.MAC) { $onlineByMac[$d.MAC] = $d.IP } }
    foreach ($d in $all.Values) { $d.MovedTo = if (-not $d.Online -and $d.MAC) { $onlineByMac[$d.MAC] } else { $null } }

    # --- Nazwy hostów: mDNS (nazwa ogłaszana przez urządzenie) oraz DNS/NetBIOS (nazwa z routera) ---
    Set-NcStatus (T 'status.names' $all.Count)
    Write-Host (T 'status.names' $all.Count) -ForegroundColor DarkGray
    $ipList = @($all.Keys)
    $mdnsNames = Resolve-MdnsReverseBatch $ipList $a.IP
    $dnsNames = Resolve-HostNameBatch $ipList
    foreach ($d in $all.Values) {
        $d.Ping      = $alive[$d.IP]
        $d.Speedwire = $sw[$d.IP]
        $d.Vendor    = Get-MacVendor $d.MAC
        $d.Name      = ''; $d.NameSrc = ''
        if ($mdnsNames[$d.IP])    { $d.Name = $mdnsNames[$d.IP]; $d.NameSrc = 'mDNS' }
        elseif ($dnsNames[$d.IP]) { $d.Name = $dnsNames[$d.IP];  $d.NameSrc = 'DNS/NetBIOS' }
        $d.SmaName   = Test-IsSmaHostName $d.Name
    }
    # Najpierw urządzenia online, potem offline; w każdej grupie według adresu IP
    $sorted = @($all.Values | Sort-Object @{ e = { if ($_.Online) { 0 } else { 1 } } }, @{ e = { ConvertTo-UInt32 $_.IP } })
    $online = @($sorted | Where-Object { $_.Online }).Count

    # Jak urządzenie odpowiedziało (albo że nie odpowiada)
    $respText = {
        param($d)
        if ($null -ne $d.Ping)  { return (T 'scan.resp.ping' $d.Ping) }
        if ($d.Speedwire)       { return (T 'scan.resp.sw') }
        if ($d.Online)          { return (T 'scan.resp.arp') }
        if ($d.MovedTo)         { return (T 'scan.resp.moved' $d.MovedTo) }
        return (T 'scan.resp.none')
    }

    # Opis i ocena urządzenia SMA (podsieć, APIPA)
    $describe = {
        param($d)
        $macTxt  = if ($d.MAC) { $d.MAC + $(if ($d.Vendor) { " ($($d.Vendor))" } else { '' }) } else { '?' }
        $pingTxt = if ($null -ne $d.Ping) { T 'word.ms' $d.Ping } else { T 'word.none' }
        $swTxt   = if ($d.Speedwire) { $d.Speedwire } else { T 'word.noresp' }
        $nameTxt = if ($d.Name) { T 'scan.name' "$($d.Name) ($($d.NameSrc))" } else { '' }
        T 'scan.detail' $d.IP $macTxt $pingTxt $swTxt $nameTxt
    }
    $report = {
        param($c, $title, $d)
        $detail = & $describe $d
        if (-not $d.Online) {
            $st = if ($d.MovedTo) { 'INFO' } else { 'WARN' }
            Add-Result $c "$title - $(T 'word.offline')" $st ($detail + ' - ' + (& $respText $d)) (T 'scan.offline.h')
        } elseif ($d.IP -like '169.254.*') {
            Add-Result $c $title 'FAIL' $detail ((T 'res.dev.apipa.h') + "`n" + (Get-SecondaryIpHint $d.IP))
        } elseif (-not (Test-InSubnet $d.IP $a.IP $a.Prefix)) {
            Add-Result $c $title 'FAIL' ($detail + ' - ' + (T 'scan.outside' $a.Network $a.Prefix)) ((T 'scan.outside.h') + "`n" + (Get-SecondaryIpHint $d.IP))
        } else {
            Add-Result $c $title 'OK' $detail
        }
    }

    # Wyniki SMA trafiają do jednej grupy "Skanowanie"
    # 1) Urządzenia z nazwą SMA... (SMA + numer seryjny)
    $byName = @($sorted | Where-Object { $_.SmaName })
    foreach ($d in $byName) { & $report $cat (T 'res.scan.byname' $d.Name) $d }
    if ($byName.Count -eq 0) { Add-Result $cat (T 'res.scan.name.none') 'INFO' (T 'res.scan.name.none.d') (T 'res.scan.name.none.h') }

    # 2) Urządzenia po prefiksie MAC SMA
    $byMac = @($sorted | Where-Object { $_.Vendor })
    foreach ($d in $byMac) { & $report $cat (T 'res.scan.bymac' $d.IP) $d }
    if ($byMac.Count -eq 0) { Add-Result $cat (T 'res.scan.mac.none') 'INFO' (T 'res.scan.mac.none.d' (Get-VendorOuiText)) (T 'res.scan.mac.none.h') }

    # 3) Urządzenia znalezione tylko przez Speedwire (np. z adresem spoza podsieci)
    $swOnly = @($sorted | Where-Object { $_.Speedwire -and -not $_.SmaName -and -not $_.Vendor })
    if ($swOnly.Count -gt 0) {
        foreach ($d in $swOnly) { & $report $cat (T 'res.scan.bysw' $d.IP) $d }
    }

    # 4) Lista wszystkich urządzeń w sieci
    $catAll = T 'cat.scan.all'
    foreach ($d in $sorted) {
        $isSmaDev = [bool]($d.SmaName -or $d.Vendor -or $d.Speedwire)
        $macTxt  = if ($d.MAC) { $d.MAC } else { '?' }
        $vendTxt = if ($d.Vendor) { " ($($d.Vendor))" } else { '' }
        $nameTxt = if ($d.Name) { $d.Name } else { '-' }
        $state   = if ($d.Online) { T 'word.online' } else { T 'word.offline' }
        $title   = "$($d.IP) - $state" + $(if ($isSmaDev) { '  [SMA]' } else { '' })
        # online = OK (zielony); offline urządzenia SMA = UWAGA; offline pozostałych = INFO
        $st = if ($d.Online) { 'OK' } elseif ($isSmaDev -and -not $d.MovedTo) { 'WARN' } else { 'INFO' }
        Add-Result $catAll $title $st (T 'scan.all.d' $macTxt $vendTxt $nameTxt (& $respText $d))
    }

    $smaCount = @($sorted | Where-Object { $_.SmaName -or $_.Vendor -or $_.Speedwire }).Count
    if ($smaCount -eq 0) {
        Add-Result $cat (T 'res.smadev') 'FAIL' (T 'res.smadev.none.d') (T 'res.smadev.none.h')
    }
    Add-Result $cat (T 'res.scanSum') 'INFO' (T 'res.scanSum.d' $sorted.Count $online ($sorted.Count - $online) $byName.Count $byMac.Count $swOnly.Count) (T 'res.scanSum.h')
}

# =====================================================================================
#  TEST 4: MULTICAST
# =====================================================================================
function Invoke-MulticastTest([int]$Seconds) {
    $a = $script:Adapter
    Invoke-AdapterCheck
    Write-Section (T 'sec.mc' $script:SpeedwireGroup $script:SpeedwirePort)
    $cat = T 'cat.multicast'
    if ($script:Interactive) {
        $ans = Read-Host (T 'prompt.listen' $Seconds)
        $v = 0; if ([int]::TryParse($ans, [ref]$v) -and $v -ge 5) { $Seconds = $v }
    }
    Test-FirewallForMulticast

    $sock = $null
    try { $sock = New-SpeedwireSocket $a.IP }
    catch {
        Add-Result $cat (T 'res.socket') 'FAIL' (T 'res.socket.d' (Get-SocketErrorText $_)) (T 'res.socket.h')
        return
    }
    Add-Result $cat (T 'res.join') 'OK' (T 'res.join.d' $script:SpeedwireGroup $a.IP)
    $grp = New-Object Net.IPEndPoint([Net.IPAddress]::Parse($script:SpeedwireGroup), $script:SpeedwirePort)
    $sendAt = @(0, 3, [int]($Seconds / 2))
    $tick = {
        param($elapsed)
        if ($sendAt -contains $elapsed) { try { [void]$sock.SendTo($script:SpeedwireDiscovery, $grp) } catch { } }
    }
    $start = Get-Date
    try { $packets = Receive-Speedwire -Socket $sock -Seconds $Seconds -Progress -OnTick $tick }
    finally { $sock.Close() }

    if ($packets.Count -eq 0) {
        Add-Result $cat (T 'res.packets') 'FAIL' (T 'res.packets.none.d' $Seconds) (T 'res.packets.none.h')
        return
    }

    # Grupowanie po źródle
    $groups = $packets | Group-Object { "$($_.IP)|$($_.Info.Kind)|$($_.Info.Serial)" }
    $meters = 0; $responders = @{}; $requesters = @{}
    foreach ($g in $groups) {
        $first = $g.Group[0]; $ip = $first.IP; $info = $first.Info
        $times = @($g.Group | ForEach-Object { $_.Time })
        $maxGap = 0
        for ($i = 1; $i -lt $times.Count; $i++) { $gap = ($times[$i] - $times[$i - 1]).TotalSeconds; if ($gap -gt $maxGap) { $maxGap = $gap } }
        $startGap = ($times[0] - $start).TotalSeconds
        $endGap = ($start.AddSeconds($Seconds) - $times[-1]).TotalSeconds
        $inSub = Test-InSubnet $ip $a.IP $a.Prefix
        $sub = if ($inSub) { '' } else { T 'mc.outside' $a.Network $a.Prefix }
        $serial = if ($info.Serial) { T 'mc.sn' $info.Serial } else { '' }

        switch ($info.Kind) {
            'EnergyMeter' {
                $meters++
                $detail = T 'mc.meter.d' $ip $serial $g.Count $Seconds ([math]::Round($maxGap, 1)) $sub
                if ($maxGap -gt 5 -or $endGap -gt 5 -or $startGap -gt 5) {
                    Add-Result $cat $info.Model 'WARN' ($detail + ' ' + (T 'mc.gaps' ([math]::Round($startGap, 1)) ([math]::Round($endGap, 1)))) (T 'mc.gap.h')
                } else {
                    Add-Result $cat $info.Model 'OK' $detail
                }
                if (-not $inSub) { Add-Result $cat "$($info.Model) $ip" 'WARN' (T 'mc.meterOut.d') (T 'mc.meterOut.h') }
            }
            'DiscoveryRequest' {
                $requesters[$ip] = $g.Count
            }
            default {
                $responders[$ip] = "$($info.Model)$serial"
            }
        }
    }
    foreach ($ip in $responders.Keys) {
        $inSub = Test-InSubnet $ip $a.IP $a.Prefix
        if ($inSub) { Add-Result $cat (T 'res.swdev' $ip) 'OK' $responders[$ip] }
        else { Add-Result $cat (T 'res.swdev' $ip) 'FAIL' ($responders[$ip] + (T 'mc.outside' $a.Network $a.Prefix)) ((T 'mc.respOut.h') + "`n" + (Get-SecondaryIpHint $ip)) }
    }
    foreach ($ip in $requesters.Keys) {
        Add-Result $cat (T 'res.discFrom' $ip) 'INFO' (T 'res.discFrom.d' $requesters[$ip])
    }
    if ($meters -eq 0) {
        Add-Result $cat (T 'res.meter') 'INFO' (T 'res.meter.none.d') (T 'res.meter.none.h')
    }
    if ($responders.Count -eq 0) {
        Add-Result $cat (T 'res.disc') 'WARN' (T 'res.disc.none.d') (T 'res.disc.none.h')
    }
    if ($Seconds -lt 260 -and $meters -gt 0) {
        Add-Result $cat (T 'res.long') 'INFO' (T 'res.long.d' $Seconds) (T 'res.long.h')
    }
}

# =====================================================================================
#  RAPORT
# =====================================================================================
function Show-Summary {
    if ($script:Results.Count -eq 0) { return }
    Write-Section (T 'sec.summary')
    $cnt = @{ OK = 0; WARN = 0; FAIL = 0; INFO = 0 }
    foreach ($r in $script:Results) { $cnt[$r.Status]++ }
    Write-Host (T 'summary.counts' $cnt.OK $cnt.WARN $cnt.FAIL $cnt.INFO)
    foreach ($r in @($script:Results | Where-Object { $_.Status -in 'FAIL', 'WARN' })) {
        $color = if ($r.Status -eq 'FAIL') { 'Red' } else { 'Yellow' }
        Write-Host (" [{0}] {1}: {2}" -f (T "tag.$($r.Status.ToLower())"), $r.Category, $r.Name) -ForegroundColor $color
    }
}

function Save-Report([string]$Path) {
    if ($script:Results.Count -eq 0) { Write-Host (T 'report.none') -ForegroundColor Yellow; return $null }
    $enc = { param($t) [Net.WebUtility]::HtmlEncode([string]$t) }
    $ts = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    if (-not $Path) {
        $dirs = @($script:ReportsDir,(Join-Path ([Environment]::GetFolderPath('Desktop')) 'SMA-NetCheck-Reports'), $env:TEMP)
        foreach ($d in $dirs) {
            try { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -ErrorAction Stop | Out-Null }; $Path = Join-Path $d "SMA-NetCheck_$($env:COMPUTERNAME)_$ts.html"; [IO.File]::WriteAllText($Path, ''); break } catch { $Path = $null }
        }
    }
    $cnt = @{ OK = 0; WARN = 0; FAIL = 0; INFO = 0 }
    foreach ($r in $script:Results) { $cnt[$r.Status]++ }
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html><html lang="$($script:Lang.ToLower())"><head><meta charset="utf-8"><title>SMA NetCheck - $ts</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222;background:#f6f7f9}
h1{margin:0 0 4px} h2{margin-top:28px;border-bottom:2px solid #ddd;padding-bottom:4px}
.meta{color:#666;font-size:13px} table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
td,th{border:1px solid #e1e3e6;padding:6px 8px;vertical-align:top;text-align:left} th{background:#eef0f3}
.s{font-weight:600;white-space:nowrap;text-align:center;width:70px}
.OK{background:#e3f6e8;color:#126b2e}.WARN{background:#fff4d6;color:#8a5a00}.FAIL{background:#fde2e1;color:#9b1c1c}.INFO{background:#e6f0fb;color:#1d4f91}
.hint{color:#6b4e00;white-space:pre-line;font-size:12px;margin-top:4px}
.badges span{display:inline-block;padding:4px 10px;border-radius:12px;margin-right:6px;font-weight:600}
</style></head><body>
<h1>$(& $enc (T 'html.title'))</h1>
<div class="meta">$(& $enc (T 'html.date')): $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &middot; $(& $enc (T 'html.computer')): $(& $enc $env:COMPUTERNAME) &middot; $(& $enc (T 'html.version')): $($script:Version) &middot; $(& $enc (T 'html.admin')): $(if ($script:IsAdmin) { & $enc (T 'word.yes') } else { & $enc (T 'word.no') })</div>
<p class="badges"><span class="OK">$(& $enc (T 'html.ok')): $($cnt.OK)</span><span class="WARN">$(& $enc (T 'html.warn')): $($cnt.WARN)</span><span class="FAIL">$(& $enc (T 'html.fail')): $($cnt.FAIL)</span><span class="INFO">$(& $enc (T 'html.info')): $($cnt.INFO)</span></p>
"@)
    [void]$sb.Append("<h2>$(& $enc (T 'html.adapters'))</h2><table><tr><th>$(& $enc (T 'html.th.adapter'))</th><th>$(& $enc (T 'html.th.ipmask'))</th><th>$(& $enc (T 'html.th.gw'))</th><th>DNS</th><th>DHCP</th><th>MAC</th><th>$(& $enc (T 'html.th.type'))</th></tr>")
    foreach ($ad in $script:AllAdapters) {
        $typ = @(); if ($ad.Wireless) { $typ += (T 'flag.wifi') }; if ($ad.Virtual) { $typ += (T 'flag.virtual') }; $typ += $ad.Category
        [void]$sb.Append("<tr><td>$(& $enc $ad.Alias)<br><small>$(& $enc $ad.Description)</small></td><td>$($ad.IP)/$($ad.Prefix)<br><small>$($ad.Mask)</small></td><td>$(& $enc $ad.Gateway)</td><td>$(& $enc ($ad.Dns -join ', '))</td><td>$($ad.Dhcp)</td><td>$($ad.Mac)</td><td>$(& $enc ($typ -join ', '))</td></tr>")
    }
    [void]$sb.Append('</table>')
    foreach ($g in ($script:Results | Group-Object Category)) {
        [void]$sb.Append("<h2>$(& $enc $g.Name)</h2><table><tr><th>$(& $enc (T 'html.th.status'))</th><th>$(& $enc (T 'html.th.test'))</th><th>$(& $enc (T 'html.th.result'))</th></tr>")
        foreach ($r in $g.Group) {
            $hint = if ($r.Hint) { "<div class='hint'>&#10148; $(& $enc $r.Hint)</div>" } else { '' }
            [void]$sb.Append("<tr><td class='s $($r.Status)'>$(& $enc (T "tag.$($r.Status.ToLower())"))</td><td>$(& $enc $r.Name)<br><small>$(& $enc $r.Adapter)</small></td><td>$(& $enc $r.Detail)$hint</td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append("<h2>$(& $enc (T 'html.req'))</h2><table><tr><th>$(& $enc (T 'html.th.service'))</th><th>$(& $enc (T 'html.th.address'))</th><th>$(& $enc (T 'html.th.port'))</th><th>$(& $enc (T 'html.th.applies'))</th></tr>")
    foreach ($t in $script:PortalTargets) {
        $proto = if ($t.Type -eq 'NTP') { 'UDP' } else { 'TCP' }
        [void]$sb.Append("<tr><td>$(& $enc (T $t.Key))</td><td>$($t.HostName)</td><td>$proto $($t.Port)</td><td>$(& $enc (T $t.ForKey))</td></tr>")
    }
    [void]$sb.Append("<tr><td>$(& $enc (T 'html.sw'))</td><td>multicast $($script:SpeedwireGroup)</td><td>UDP 9522</td><td>$(& $enc (T 'html.sw.applies'))</td></tr>")
    [void]$sb.Append("</table><p>$(& $enc (T 'html.status')): <a href='$($script:StatusPageUrl)' target='_blank'>$($script:StatusPageUrl)</a></p>")
    [void]$sb.Append("<p class='meta'>$(& $enc (T 'html.footer'))</p></body></html>")
    try {
        [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($true)))
        Write-Host (T 'report.saved' $Path) -ForegroundColor Green
        return $Path
    } catch {
        Write-Host (T 'report.fail' $_.Exception.Message) -ForegroundColor Red
        return $null
    }
}

# =====================================================================================
#  MENU / START
# =====================================================================================
function Show-Header {
    Write-Host ''
    Write-Host '  ____  __  __    _      _   _      _    ____ _               _    ' -ForegroundColor DarkCyan
    Write-Host ' / ___||  \/  |  / \    | \ | | ___| |_ / ___| |__   ___  ___| | __' -ForegroundColor DarkCyan
    Write-Host ' \___ \| |\/| | / _ \   |  \| |/ _ \ __| |   | ''_ \ / _ \/ __| |/ /' -ForegroundColor DarkCyan
    Write-Host '  ___) | |  | |/ ___ \  | |\  |  __/ |_| |___| | | |  __/ (__|   < ' -ForegroundColor DarkCyan
    Write-Host ' |____/|_|  |_/_/   \_\ |_| \_|\___|\__|\____|_| |_|\___|\___|_|\_\' -ForegroundColor DarkCyan
    $adm = if ($script:IsAdmin) { '  [' + (T 'hdr.admin') + ']' } else { '' }
    Write-Host ((T 'hdr.subtitle' $script:Version) + $adm) -ForegroundColor Gray
}

function Show-Menu {
    while ($true) {
        $a = $script:Adapter
        Write-Host ''
        Write-Host ('-' * 78) -ForegroundColor DarkGray
        Write-Host (T 'menu.adapter' $a.Alias $a.IP $a.Prefix (Format-Value $a.Gateway)) -ForegroundColor White
        Write-Host ('-' * 78) -ForegroundColor DarkGray
        foreach ($k in 'menu.1', 'menu.2', 'menu.3', 'menu.4', 'menu.5', 'menu.6', 'menu.7', 'menu.8', 'menu.0') { Write-Host ('  ' + (T $k)) }
        $c = Read-Host (T 'prompt.choice')
        switch ($c) {
            '1' { $sel = Select-Adapter -Ask; if ($sel) { $script:Adapter = $sel } }
            '2' { Invoke-PortalTest }
            '3' { Invoke-LocalTest @() }
            '4' { Invoke-SubnetScan $ScanRange }
            '5' { Invoke-MulticastTest $ListenSeconds }
            '6' {
                $d = Read-Host (T 'prompt.devicesFull')
                Invoke-PortalTest; Invoke-SubnetScan $ScanRange; Invoke-MulticastTest $ListenSeconds
                $list = @($d -split '[,;\s]+' | Where-Object { $_ })
                if ($list.Count -gt 0) { Invoke-LocalTest $list }
                Show-Summary
            }
            '7' {
                Show-Summary
                $p = Save-Report $ReportPath
                if ($p) { $o = Read-Host (T 'prompt.openReport'); if ($o -eq '' -or $o -match $script:YesPattern) { Start-Process $p } }
            }
            '8' {
                $l = Read-Host (T 'prompt.lang')
                if ($script:LangCodes -contains $l.ToUpper()) { Set-NcLanguage $l; [void](Save-NcLanguage $script:Lang) }
            }
            '0' {
                if ($script:Results.Count -gt 0 -and -not $NoReport) {
                    $s = Read-Host (T 'prompt.saveBeforeExit')
                    if ($s -eq '' -or $s -match $script:YesPattern) { Show-Summary; [void](Save-Report $ReportPath) }
                }
                return
            }
            default { Write-Host (T 'menu.unknown') -ForegroundColor Yellow }
        }
    }
}

# ------------------------------------------------------------------ main
# Przy dołączeniu kropką (". .\SMA-NetCheck.ps1", np. z GUI) ładowane są tylko funkcje.
if ($MyInvocation.InvocationName -eq '.') { return }
try {
    Show-Header
    [void](Clear-LeftoverFirewallRule)   # sprzątanie po ewentualnym przerwanym teście
    $script:Adapter = Select-Adapter -Ask:($script:Interactive -and -not $Interface)
    if (-not $script:Adapter) { return }
    Write-Host (T 'main.using' $script:Adapter.Alias $script:Adapter.IP $script:Adapter.Prefix) -ForegroundColor Green

    switch ($Mode) {
        'Menu'      { Show-Menu }
        'Portal'    { Invoke-PortalTest }
        'Local'     { Invoke-LocalTest $Device }
        'Scan'      { Invoke-SubnetScan $ScanRange }
        'Multicast' { Invoke-MulticastTest $ListenSeconds }
        'Full'      {
            Invoke-PortalTest; Invoke-SubnetScan $ScanRange; Invoke-MulticastTest $ListenSeconds
            if ($Device) { Invoke-LocalTest $Device }
        }
    }
    if ($Mode -ne 'Menu') {
        Show-Summary
        if (-not $NoReport) { [void](Save-Report $ReportPath) }
    }
} finally {
    Remove-TempFirewallRule
}
