# myVPN for Windows

Your own WireGuard VPN, with a Windows app to create profiles and turn the
connection on or off. You keep the server, keys, and configuration under your
control. WireGuard provides the encryption; this project does not invent a new
VPN protocol or use a commercial VPN subscription.

**This is a first version, not a deployed VPN service.** You still need to set up
a server. Use a free local Ubuntu virtual machine to learn and test, then a
reachable remote Linux machine for a remote internet exit. There is no included
server or guaranteed free cloud hosting.

## Start on your Windows PC

You need Windows 10/11, administrator access, and the free official
[WireGuard for Windows](https://www.wireguard.com/install/). No Python, Node.js,
PowerShell 7, or paid account is required on Windows.

1. Install WireGuard from its official website.
2. Download and extract the entire project ZIP into a folder. Do not run from
   inside the ZIP. If using Git, clone this repository instead.
3. Double-click **`MyVPN.cmd`** and approve the Windows administrator prompt.
4. Click **Create a VPN**. Enter your server's IP address or hostname. For your
   first free test, use an Ubuntu VM's LAN IPv4 address as explained in the
   [server guide](docs/server.md). Port `51820` is the default.
5. The app generates a server profile (`wg0.conf`) and PC profile (`myvpn.conf`),
   then loads the PC profile. Use **Open setup folder** to find them. Follow the
   [server guide](docs/server.md) to install the server profile on your VM/server.
6. Click **Connect**. The app first waits for the server. A recent encrypted
   handshake changes the status to **Server responded**.
7. Complete the guide's ping, DNS, and public-IP checks before relying on it for
   browsing. Click **Disconnect** to restore your ordinary connection.

The server installer runs on the chosen **Linux server**, not on Windows.
Config generation alone does not create that server. For a remote server you
need an inbound-reachable address and the selected UDP port allowed/forwarded.

## One click and portability

Once your server and profile are set up, **Connect** starts the VPN and
**Disconnect** stops it. For a direct launcher, double-click **`Connect.cmd`**;
it connects immediately and opens the status window. **`Disconnect.cmd`** turns
it off. You can create desktop shortcuts to these files.

Windows may ask for administrator approval when you
open the app. Closing the window leaves the VPN on; reopen the app to disconnect.
The Windows tunnel uses manual startup, so it does not automatically connect
after reboot. Use **Reset stopped tunnel** if a previously installed tunnel
stopped before reconnecting or changing profiles.

The app is a folder you can copy. Each PC still needs the official WireGuard
driver/app installed and administrator access. Private profiles live in
`%LOCALAPPDATA%\MyVPN`, **not in the portable folder**. To move an identity to
another PC, transfer its client profile privately and use **Import profile**.
Do not run the same peer identity on two devices simultaneously. This version
manages one client profile and one server peer.

The default generated client routes IPv4 and IPv6 into the tunnel. This server
version provides IPv4 internet and deliberately rejects IPv6 internet traffic.
Windows WireGuard applies its restrictive firewall behavior for the generated
full-tunnel configuration. This app does not add a permanent, always-on kill
switch: disconnecting restores ordinary internet access. Imported split-tunnel
profiles can behave differently. See WireGuard's
[Windows networking documentation](https://git.zx2c4.com/wireguard-windows/about/docs/netquirk.md).

## Free test first, remote exit later

```text
Windows PC --> encrypted WireGuard tunnel --> your Linux server --> internet
```

A bridged Ubuntu VM on your PC is a free learning lab. It normally shares your
home public IP; it does not put you in another country or hide traffic from your
home ISP. A remote machine you control gives you that machine's internet exit.
Hosting may have a cost. A home server lets you connect home while travelling,
but inbound access can be blocked by your ISP's carrier-grade NAT.

## Your keys and files

Generated setups are stored under:

```text
%LOCALAPPDATA%\MyVPN\setups\setup-<date>-<random>\
    wg0.conf      server profile: copy privately to Linux
    myvpn.conf    Windows profile: keep on your PC
    setup.json    non-secret setup information
```

The active client profile is `%LOCALAPPDATA%\MyVPN\myvpn-desktop.conf`. The app
restricts its data directory to your Windows account, Administrators, and SYSTEM.
Each new setup generates new keys and a new folder. It never overwrites an old
generated setup, but loading a new client profile replaces the active client
copy after you disconnect. An existing server keeps its old keys until you
deliberately migrate it; the installer refuses to overwrite changed server files.

Configuration files contain **private keys**. Do not post them, add them to Git,
or include them in screenshots. The repository ignores common key/profile file
extensions, and the packaging tool excludes generated profiles. Keep backups
private. If a private key is exposed, replace that identity and its matching peer
configuration.

## Later: your old router

The Windows application does not run on a router. A compatible router runs its
own WireGuard client and uses a matching configuration. Some routers support
WireGuard directly; some support OpenWrt; some support neither. The exact model
and hardware revision are needed before selecting firmware or router commands.

Do not use the Windows peer key on a router at the same time as the PC. A separate
router peer is the next development step; this first version does not automate
multiple peers or firmware flashing.

## Learn from the code

| File | Purpose |
| --- | --- |
| `MyVPN.cmd` | Opens the app with built-in Windows PowerShell |
| `Connect.cmd` / `Disconnect.cmd` | Direct connection and disconnection launchers |
| `windows/MyVPN.ps1` | Native Windows Forms interface and administrator prompt |
| `windows/MyVPN.Core.psm1` | Validates inputs and generates keys using official `wg.exe` |
| `windows/MyVPN.Controller.psm1` | Imports profiles and controls the owned Windows tunnel service |
| `server/install-server.sh` | Installs the generated server on Debian/Ubuntu |
| `server/myvpn-firewall.sh` | Adds/removes scoped forwarding and NAT rules |
| `docs/server.md` | Free VM lab, remote deployment, connection tests, router guidance |

The launcher uses a process-only PowerShell execution-policy override to run the
included local scripts; it does not change your saved system execution policy.
It never requests your administrator password itself; elevation uses Windows UAC.

You can generate profiles from Windows PowerShell too:

```powershell
Import-Module .\windows\MyVPN.Core.psm1
New-MyVpnConfiguration -Endpoint 'YOUR-SERVER-IP:51820' `
    -OutputDirectory "$env:LOCALAPPDATA\MyVPN\setups\my-first-server"
```

Replace `YOUR-SERVER-IP` with your actual address. Use a new output directory.
The optional `-SplitTunnel` switch routes only the private tunnel networks and
does not override your DNS; it is for accessing the server, not VPN internet
browsing. The GUI creates full-tunnel profiles.

## Development checks

In Windows PowerShell, from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-All.ps1
```

The ordinary tests require neither admin access nor a live VPN. They cover input
validation, generated profiles, profile parsing, handshake interpretation, and
service ownership/transition logic using test doubles. For actual Windows
key generation and file-permission checks, with WireGuard installed:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Windows.ps1
```

Linux server validation tests (no firewall changes or network interfaces created):

```bash
bash tests/test-server.sh
bash tests/test-firewall.sh
```

Build a secret-free ZIP on a development machine with Python 3:

```bash
python3 tools/package.py
```

The output is `dist/MyVPN-windows.zip`. Python is only for packaging, not for
running the Windows app. See [validation notes](docs/validation.md) for exactly
what was and was not tested in the Linux development environment.
