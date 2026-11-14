===============================================================================
  SMA NetCheck
===============================================================================

Portable network diagnostic tool for SMA installers and support.
No installation required. Runs on Windows 10 / 11 (Windows PowerShell 5.1).


-------------------------------------------------------------------------------
  HOW TO START
-------------------------------------------------------------------------------

  OPTION A - one command (no manual download)

    Open PowerShell (Start -> type "powershell" -> Enter) and paste:

      irm https://raw.githubusercontent.com/Nightry/SMA-NetCheck/main/get.ps1 | iex

    It downloads the latest release, extracts it to
    %LOCALAPPDATA%\SMA-NetCheck and starts the program window. Run the same
    command again next time - it always updates to the latest version.
    Reports are saved to %LOCALAPPDATA%\SMA-NetCheck\Reports.

  OPTION B - download the ZIP

  1. Download SMA-NetCheck.zip from
     https://github.com/Nightry/SMA-NetCheck/releases/latest
     (or on GitHub: Code -> Download ZIP).

  2. Extract the WHOLE archive: right-click the ZIP -> "Extract All".
     Do not run the program directly from inside the ZIP.

  3. Double-click:   Start-SMA-NetCheck.cmd

  If Windows shows a warning about a file from the Internet, choose "Run".
  To avoid it: before extracting, right-click the ZIP -> Properties ->
  tick "Unblock" -> OK.

  The "app" folder contains the program files - you do not need to open
  anything in it. HTML reports are saved to the "Reports" folder next to
  Start-SMA-NetCheck.cmd (if it is not writable: Desktop or %TEMP%).

  Note: the .ps1 files cannot be started with right-click -> "Run with
  PowerShell" - Windows blocks scripts by default.
  Always use Start-SMA-NetCheck.cmd.


-------------------------------------------------------------------------------
  FILE STRUCTURE
-------------------------------------------------------------------------------

  Start-SMA-NetCheck.cmd                    Double-click - opens the program
  README.txt                                This file
  app\SMA-NetCheck-GUI.ps1                  Graphical interface (window)
  app\SMA-NetCheck.ps1                      Test script (also with parameters)
  app\SMA-NetCheck.lang.ps1                 PL / EN / DE texts (required)
  app\Start-SMA-NetCheck-Console.cmd        Advanced: console version
  app\Start-SMA-NetCheck-Console-Admin.cmd  Same, as administrator

  The whole folder (start file + "app") can be copied e.g. to a USB stick.


-------------------------------------------------------------------------------
  PROGRAM WINDOW
-------------------------------------------------------------------------------

  Left panel:
    - network adapter selection and its details (Cable / Wi-Fi / VPN /
      no gateway / APIPA),
    - test selection and multicast listening time (20 s - 10 min),
    - optional "Custom IP range" for the network scan, e.g. 192.168.1.1-255,
      192.168.1.10-192.168.1.50 or 192.168.1.0/24 (up to 1024 addresses);
      if not ticked, the subnet of the selected adapter is scanned,
    - device list: IP address or serial number, one per line
      (782354782 and SMA782354782 both work),
    - temporary Windows Firewall rule (administrator only).

  Right panel:
    - verdict (e.g. "Problems detected") with the most important errors,
    - counters Errors / Warnings / OK / Information,
    - results grouped by test; every problem comes with a hint on what to
      check.

  Buttons:
    - Stop                      stops the running test,
    - Show problems only        filters the list,
    - Copy results              copies text to the clipboard (e.g. for a
                                ticket or e-mail),
    - Save HTML report          saves the report,
    - About                     (in the window header) opens README.txt,
    - Run as administrator      (in the window header, shown only without
                                administrator rights),
    - SMA server status         (in the window header) opens
                                https://sunnyportal.statuspage.io/
                                - current outages and maintenance on the SMA
                                side. The link is also shown in the portal
                                test results and in the HTML report.

  Tests run in the background, the window does not freeze and results appear
  as they come in.


-------------------------------------------------------------------------------
  LANGUAGES (PL / EN / DE)
-------------------------------------------------------------------------------

  - In the window: language selector in the header (globe icon). The change
    applies immediately. Results already shown stay in the previous language;
    new tests and the HTML report use the selected language.
  - In the console: menu option 8 or the parameter -Language PL|EN|DE.
  - First start: always English. Switch the language in the header; the
    choice is remembered for the next starts.
  - The choice is saved in app\SMA-NetCheck.settings.json (if the folder is
    read-only: %APPDATA%\SMA-NetCheck\settings.json).
  - Texts are stored in app\SMA-NetCheck.lang.ps1, format:
        'key' = @('PL', 'EN', 'DE')
      {0}, {1} ... = inserted values (every translation must have the same),
      \n           = new line,
      ''           = apostrophe inside a text.
    Translation fixes do not require code changes.


-------------------------------------------------------------------------------
  WHAT THE PROGRAM CHECKS
-------------------------------------------------------------------------------

  Network adapter (automatically before the tests)
    All tests are sent from the address of the selected adapter. Checks the
    configuration, APIPA (169.254.x.x), subnet mask, gateway (ping), DNS,
    Wi-Fi, VPN / virtual adapters, the same subnet on several adapters and
    the Windows network profile.

  1. SMA portal connection
     - proxy,
     - DNS servers from DHCP and public 8.8.8.8 / 1.1.1.1 (query for
       ennexos.sunnyportal.com) - tells a blocked local DNS from a blocked
       public DNS,
     - DNS filter (private address or 0.0.0.0 instead of the SMA address),
     - TCP connection, TLS handshake and HTTP response,
     - SSL inspection (replaced certificate); the private SMA CA
       ("Sunny Portal CA") is recognised as valid,
     - NTP with clock offset measurement and port 9524 (Webconnect / HM-20),
     - control targets (microsoft.com, 1.1.1.1) to tell "no Internet" from
       "only SMA blocked",
     - link to the SMA server status page.

  2. Network scan (or the custom IP range)
     Ping of every address in the subnet (up to /22), ARP table, Speedwire
     discovery (multicast) and the name of every device found (mDNS - the
     name the device announces itself, DNS / NetBIOS - the name registered
     in the router). SMA devices found in three ways are shown together
     in the "Scan" group, followed by the list of all devices:
     - SMA by name: hostname starting with SMA followed by a non-letter,
       e.g. SMA782354782 (names like "Smart-TV" are not matched),
     - SMA by MAC address: SMA prefixes 00:40:AD, 00:15:BB (IEEE registry)
       and AC:19:9F (used by some SMA inverters),
     - SMA via Speedwire only: also finds devices in the same network
       segment that have an IP address from ANOTHER subnet - a typical
       reason why the master does not see a device,
     - all devices in the network: IP, MAC, vendor, name and current state:
         online  - answers now (ping, Speedwire or a fresh ARP request,
                   so devices that block ping are detected too),
         offline - remembered by Windows from earlier (ARP cache), but does
                   not answer now; if the same MAC is online at another
                   address, the device got a new IP address.
       Online devices are listed first. Offline SMA devices are also marked
       in the SMA lists.

  3. Multicast
     Joins the group 239.12.255.254:9522, sends discovery and listens.
     Shows:
     - Energy Meter / Sunny Home Manager 2.0 with serial number, packet count
       and the longest gap,
     - devices answering discovery and hosts sending discovery themselves
       (probably the master),
     - gaps in the stream - a test of 5 min or longer detects IGMP snooping
       without a querier (multicast disappears after a few minutes),
     - Windows Firewall state and network profile (in the Public profile a
       false negative is possible).

  4. Devices in the local network (IP / serial number)
     - name resolution via DNS, mDNS (.local) and NetBIOS/LLMNR, detecting
       inconsistent (stale) entries,
     - subnet, APIPA, ping and ARP/MAC (SMA prefix, see above),
     - ports 443, 80, 502 and a Speedwire request to the device,
     - web interface (HTTPS) at every address the browser can use to open it:
           https://192.168.x.x
           https://SMA782354782         (DNS / NetBIOS / LLMNR)
           https://SMA782354782.local   (mDNS)
       with a summary of which addresses work. You can also paste an address
       straight from the browser, e.g. https://SMA782354782.local/
     - for devices in another subnet, a ready-made netsh command that adds a
       temporary second IP address to the laptop.

  The HTML report contains all results and a table of required addresses
  and ports to hand over to the customer's network administrator.


-------------------------------------------------------------------------------
  CHECKED ADDRESSES (CONFIGURATION section at the top of app\SMA-NetCheck.ps1)
-------------------------------------------------------------------------------

  Service                             Address                       Port
  ----------------------------------  ----------------------------  --------
  ennexOS - user interface            ennexos.sunnyportal.com       TCP 443
  ennexOS - data transmission         ldm-devapi.sunnyportal.com    TCP 443
  Firmware updates                    update.sunnyportal.de         TCP 443
  NTP                                 ntp.sunny-portal.com          UDP 123
  Webconnect 1.5 / SMA SPOT / HM-20   wco.sunnyportal.com           TCP 9524
  Sunny Portal classic                www.sunnyportal.com           TCP 443
  Speedwire (LAN)                     239.12.255.254 (multicast)    UDP 9522

  The SMA article contains the typo "Idm-devapi". The name
  idm-devapi.sunnyportal.com does not exist in DNS, the correct one is
  ldm-devapi.sunnyportal.com (checked 2026-11-12).


-------------------------------------------------------------------------------
  IPv4 ONLY
-------------------------------------------------------------------------------

  SMA devices support IPv4 only, so all tests are forced over IPv4, even if
  the laptop also has IPv6:
  - all TCP/UDP connections are IPv4 and leave from the selected adapter,
  - names are resolved to IPv4 addresses only, via IPv4 DNS servers,
  - ping, ARP, mDNS, Speedwire and NTP use IPv4 addresses only.
  If IPv6 is active on the adapter, the results show "IPv4 mode" with the
  list of ignored IPv6 addresses.


-------------------------------------------------------------------------------
  LIMITATIONS
-------------------------------------------------------------------------------

  - The portal test checks the network from the laptop's point of view. The
    laptop must be in the same VLAN / port as the master, because the
    firewall may have separate rules for the devices' IP or MAC addresses.
  - Windows Firewall or antivirus software may block incoming multicast. In
    that case restart the program as administrator (button in the window
    header - temporary firewall rule) or accept the firewall prompt.
  - Recognised meter models: SusyID 270, 349, 372. Other devices are shown
    with their SusyID only.


-------------------------------------------------------------------------------
  ADVANCED: RUNNING WITH PARAMETERS
-------------------------------------------------------------------------------

  From the program folder (script block bypassed for this run only):

    powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Full -Interface Ethernet -Device SMA782354782,192.168.1.50 -ListenSeconds 300
    powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Portal -Interface "Wi-Fi"
    powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Multicast -ListenSeconds 300 -AddFirewallRule
    powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Full -Language DE

  -Mode       Menu | Portal | Local | Scan | Multicast | Full
  -Interface  adapter alias, index or IP
  Other:      -Device, -ScanRange (custom scan range), -ListenSeconds,
              -AddFirewallRule (as administrator),
              -Language PL|EN|DE, -ReportPath, -NoReport

  EXE version (optional) - with the PS2EXE module:
    Install-Module ps2exe -Scope CurrentUser
    Invoke-PS2EXE .\app\SMA-NetCheck.ps1 .\SMA-NetCheck.exe -title "SMA NetCheck" -version 1.1.0
  Note: EXE files built with PS2EXE are often flagged by antivirus software.
  The safest option is to sign it with a company certificate or to stay with
  .cmd + .ps1.
