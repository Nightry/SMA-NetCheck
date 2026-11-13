# SMA NetCheck

Portable network diagnostic tool for SMA installers and support.
No installation required. Runs on Windows 10 / 11 (Windows PowerShell 5.1). User interface in English, Polish and German.

## How to start

1. Download the ZIP: **Code → Download ZIP** (or the file from **Releases**).
2. Extract the **whole** archive: right-click the ZIP → **Extract All**.
   Do not run the program directly from inside the ZIP.
3. Double-click **`Start-SMA-NetCheck.cmd`**.

> If Windows warns about a file from the Internet, choose **Run**. To avoid the warning, right-click the ZIP
> before extracting → **Properties** → tick **Unblock** → OK.

The `app` folder contains the program files, so there is no need to open anything in it. HTML reports are saved
to the `Reports` folder next to `Start-SMA-NetCheck.cmd` (if it is not writable: Desktop or `%TEMP%`).

> The `.ps1` files cannot be started with right-click → **Run with PowerShell**, because Windows blocks scripts
> by default. Always use `Start-SMA-NetCheck.cmd`.

## File structure

| File | Purpose |
|---|---|
| **`Start-SMA-NetCheck.cmd`** | **Double-click: opens the program window** |
| `README.txt` | The same documentation as plain text (opens in Notepad) |
| `app\SMA-NetCheck-GUI.ps1` | Graphical interface (WPF) |
| `app\SMA-NetCheck.ps1` | Test script (can also be run with parameters, see below) |
| `app\SMA-NetCheck.lang.ps1` | PL / EN / DE texts (required) |
| `app\Start-SMA-NetCheck-Console.cmd` | Advanced: console version (menu) |
| `app\Start-SMA-NetCheck-Console-Admin.cmd` | Same, as administrator |

The whole folder (start file + `app`) can be copied, for example to a USB stick.

## Program window

- **Left panel:**
  - network adapter selection and its details (Cable / Wi-Fi / VPN / no gateway / APIPA);
  - test selection and multicast listening time (20 s – 10 min);
  - device list: hostname or IP address, one per line (hostname in the form SMA + serial number, e.g. `SMA782354782`);
  - temporary Windows Firewall rule (administrator only).
- **Right panel:**
  - verdict (e.g. "Problems detected") with the most important errors;
  - counters: Errors / Warnings / OK / Information;
  - results grouped by test. Every problem comes with a hint on what to check.
- **Buttons:**
  - **Stop** stops the running test;
  - **Show problems only** filters the list;
  - **Copy results** copies the results as text to the clipboard (e.g. for a ticket or e-mail);
  - **Save HTML report** saves the report;
  - **Restart as administrator** is in the window header;
  - **SMA server status** (window header) opens <https://sunnyportal.statuspage.io/> with current outages and
    maintenance on the SMA side. The link is also shown in the portal test results and in the HTML report.
- Tests run in the background. The window does not freeze and results appear as they come in.

## Languages (PL / EN / DE)

- **In the window:** language selector in the header (globe icon). The change applies immediately. Results already
  shown stay in the previous language; new tests and the HTML report use the selected language.
- **In the console:** menu option `8` or the parameter `-Language PL|EN|DE`.
- **First start:** always English. Switch the language in the header; the choice is remembered for the next starts.
- The choice is saved in `app\SMA-NetCheck.settings.json`. If the folder is read-only, it goes to
  `%APPDATA%\SMA-NetCheck\settings.json`.
- **Texts** are stored in `app\SMA-NetCheck.lang.ps1`, in the format `'key' = @('PL', 'EN', 'DE')`:
  - `{0}`, `{1}` … are inserted values (every translation must have the same ones);
  - `\n` is a new line;
  - `''` is an apostrophe inside a text.

  Translation fixes do not require code changes.

## What the program checks

**Network adapter** (automatically before the tests). All tests are sent from the address of the selected adapter.
Checks:
- the configuration, APIPA (169.254.x.x), subnet mask, gateway (ping) and DNS;
- Wi-Fi, VPN and virtual adapters, and the same subnet on several adapters;
- the Windows network profile.

1. **SMA portal connection**
   - proxy;
   - DNS servers from DHCP and the public 8.8.8.8 / 1.1.1.1 (query for `ennexos.sunnyportal.com`). Tells a
     blocked local DNS from a blocked public DNS;
   - DNS filter (private address or 0.0.0.0 instead of the SMA address);
   - TCP connection, TLS handshake and HTTP response;
   - **SSL inspection** (replaced certificate). The private SMA CA ("Sunny Portal CA") is recognised as valid;
   - NTP with clock offset measurement, and port 9524 (Webconnect / HM-20);
   - control targets (microsoft.com, 1.1.1.1), to tell "no Internet" from "only SMA blocked";
   - link to the SMA server status page.
2. **Network scan.** Pings every address in the subnet (up to /22), reads the ARP table (SMA MAC prefix
   `00:40:AD`) and runs Speedwire discovery (multicast). Discovery also finds devices in the same network segment
   that have an IP address from **another subnet**. This is a typical reason why the master does not see a device.
3. **Speedwire multicast.** Joins the group 239.12.255.254:9522, sends discovery and listens. Shows:
   - Energy Meter / Sunny Home Manager 2.0 with serial number, packet count and the longest gap;
   - devices answering discovery, and hosts sending discovery themselves (probably the master);
   - gaps in the stream. **A test of 5 min or longer** detects IGMP snooping without a querier: multicast
     disappears after a few minutes;
   - Windows Firewall state and network profile (in the Public profile a false negative is possible).
4. **Devices in the local network (hostname / IP)**
   - name resolution via DNS, mDNS (`.local`) and NetBIOS/LLMNR, detecting inconsistent (stale) entries;
   - subnet, APIPA, ping and ARP/MAC (prefix `00:40:AD` = SMA);
   - ports 443, 80 and 502, and a Speedwire request to the device;
   - **web interface** (HTTPS) at every address the browser can use to open it, with a summary of which
     addresses work:
     - `https://192.168.x.x`
     - `https://SMA782354782` (DNS / NetBIOS / LLMNR)
     - `https://SMA782354782.local` (mDNS)

     An address can also be pasted straight from the browser, e.g. `https://SMA782354782.local/`;
   - for devices in another subnet, a ready-made `netsh` command that adds a temporary second IP address to the
     laptop.

The **HTML report** contains all results and a table of required addresses and ports to hand over to the
customer's network administrator.

## Checked addresses

These are defined in the CONFIGURATION section at the top of `app\SMA-NetCheck.ps1`.

| Service | Address | Port |
|---|---|---|
| ennexOS – user interface | ennexos.sunnyportal.com | TCP 443 |
| ennexOS – data transmission | **ldm-devapi**.sunnyportal.com | TCP 443 |
| Firmware updates | update.sunnyportal.de | TCP 443 |
| NTP | ntp.sunny-portal.com | UDP 123 |
| Webconnect 1.5 / SMA SPOT / HM-20 | wco.sunnyportal.com | TCP 9524 |
| Sunny Portal classic | www.sunnyportal.com | TCP 443 |
| Speedwire (LAN) | 239.12.255.254 (multicast) | UDP 9522 |

> The SMA article contains the typo "Idm-devapi". The name `idm-devapi.sunnyportal.com` does not exist in DNS;
> the correct one is `ldm-devapi.sunnyportal.com` (checked 2026-11-12).

## IPv4 only

SMA devices support IPv4 only, so all tests are forced over IPv4, even if the laptop also has IPv6:

- all TCP/UDP connections are IPv4 and leave from the selected adapter;
- names are resolved to IPv4 addresses only, via IPv4 DNS servers;
- ping, ARP, mDNS, Speedwire and NTP use IPv4 addresses only.

If IPv6 is active on the adapter, the results show "IPv4 mode" with the list of ignored IPv6 addresses.

## Limitations

- The portal test checks the network from the laptop's point of view. The laptop must be in the same VLAN / port as
  the master, because the firewall may have separate rules for the devices' IP or MAC addresses.
- Windows Firewall or antivirus software may block incoming multicast. In that case, restart the program as
  administrator (button in the window header; it adds a temporary firewall rule) or accept the firewall prompt.
- Recognised meter models: SusyID 270, 349 and 372. Other devices are shown with their SusyID only.

## Advanced: running with parameters

From the program folder (the script block is bypassed for this run only):

```powershell
powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Full -Interface Ethernet -Device SMA782354782,192.168.1.50 -ListenSeconds 300
powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Portal -Interface "Wi-Fi"
powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Multicast -ListenSeconds 300 -AddFirewallRule
powershell -ExecutionPolicy Bypass -File .\app\SMA-NetCheck.ps1 -Mode Full -Language DE
```

- `-Mode`: `Menu | Portal | Local | Scan | Multicast | Full`.
- `-Interface`: adapter alias, index or IP address.
- Other parameters:
  - `-Device`;
  - `-ListenSeconds`;
  - `-AddFirewallRule` (as administrator);
  - `-Language PL|EN|DE`;
  - `-ReportPath`;
  - `-NoReport`.

### EXE version (optional)

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-PS2EXE .\app\SMA-NetCheck.ps1 .\SMA-NetCheck.exe -title "SMA NetCheck" -version 1.1.0
```

EXE files built with PS2EXE are often flagged by antivirus software. The safest option is to sign the EXE with a
company certificate, or to keep using `.cmd` + `.ps1`.
