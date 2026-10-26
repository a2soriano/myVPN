# Run your own VPN server

The Windows app is the client. **It cannot provide an internet VPN until another
machine runs the server.** Keep the server under your control: a spare Linux PC,
a Linux virtual machine, or a Linux server you rent. WireGuard itself costs
nothing; electricity, an internet connection, and a remote host may cost money.
There is no bundled third-party VPN service or promised free cloud account.

This first version has one Windows client. Both sides use IPv4 for internet
traffic. IPv6 is routed into the tunnel and deliberately blocked from being
forwarded to the internet, so an existing IPv6 connection cannot bypass this
IPv4-only VPN. It is not a complete anonymity system.

## First experiment: a free local VM

1. Install a supported virtualization application on Windows. Hyper-V is
   available on supported Windows Pro/Enterprise editions; VirtualBox is an
   alternative. Obtain software and an Ubuntu Server LTS ISO from their official
   websites. The app does not download or install a hypervisor for you.
2. Create a small Ubuntu Server VM (for example 2 CPU cores, 2 GB RAM, 10 GB disk).
   Use **bridged networking / an external virtual switch**, so the VM has its own
   reachable LAN address. Avoid NAT networking for this first full-tunnel test:
   the VM's traffic could depend on Windows' own tunnel routing.
3. Inside Ubuntu, run `hostname -I` and `ip -4 route show default`. Note its LAN
   IPv4 address (for example `192.168.1.60`) and uplink interface (for example
   `enp0s3`). Keep the VM console open in case a networking mistake interrupts SSH.
4. In the Windows app, generate a setup with that LAN address as its **server
   endpoint**. Use UDP port `51820` for the local VM. Your actual address will
   differ from the example. The Windows app stores the generated configurations
   in the folder it shows; the Linux server needs only `wg0.conf`.
5. Copy `wg0.conf` and this repository's `server` directory to the VM using a
   shared folder or `scp`. Use a private folder: `wg0.conf` contains a private
   key. Never commit it or post its contents. If SSH is enabled, this is an
   example from PowerShell (substitute your user, address, and actual config path):

   ```powershell
   scp "C:\path\to\generated\wg0.conf" youruser@192.168.1.60:~/wg0.conf
   scp -r .\server youruser@192.168.1.60:~/server
   ```

6. On the VM, protect the uploaded key and run the installer:

   ```bash
   chmod 600 ~/wg0.conf
   sudo bash ~/server/install-server.sh --config ~/wg0.conf --interface enp0s3
   ```

   Replace `enp0s3` with your VM's real uplink. Omitting `--interface` uses the
   device in its IPv4 route to `1.1.1.1`; this is a local route lookup, not an
   external request. Linux needs IPv6 support enabled for the private tunnel
   addresses, even though this setup does not provide IPv6 internet access.

7. Connect in the Windows app and complete the checks below.

**Expected result:** encrypted traffic travels between Windows and your VM,
and browsing exits through the VM. Since both use your home connection, your
public IP will ordinarily remain the same. This is a useful functional lab,
not a different-country IP or protection from your home internet provider.

## Install on a real remote server

Use a fresh Debian/Ubuntu machine with systemd and an IPv4 internet uplink.
Generate a **new setup** whose endpoint is the server's reachable public IPv4
address or DNS name. Copy only the server configuration to it and run the same
installer. The Windows client keeps `myvpn.conf`; the server keeps `wg0.conf`.
Do not replace either endpoint's keys while expecting an old configuration to
keep working.

The installer:

- Uses signed distribution packages (`wireguard-tools`, `iptables`, `iproute2`)
  without disabling signature or TLS verification. On some older distributions,
  kernel WireGuard support may also need a supported distribution kernel update.
- Validates the expected one-client configuration, rejecting arbitrary
  `wg-quick` hooks and other directives before running anything as root.
- Installs the server configuration in `/etc/wireguard/wg0.conf` with mode `600`.
  It never prints private keys. It refuses to replace an unrelated `wg0` or a
  changed previously managed configuration.
- Enables IPv4 forwarding using `/etc/sysctl.d/70-myvpn-forwarding.conf`.
- Installs `/usr/local/lib/myvpn/firewall.sh`. Its `wg-quick` hooks add only tagged
  rules for the chosen UDP port, client-to-server IPv4 ping, IPv4 forwarding, and
  IPv4 masquerade for this tunnel. They
  explicitly reject forwarded IPv6 from `wg0`. Stopping the tunnel removes those
  tagged rules; the helper never flushes an existing firewall.
- Enables `wg-quick@wg0` on boot. An unchanged rerun is safe and does not restart
  an already running tunnel. The installer does not implement key rotation.

This intentionally grants the generated client internet forwarding through the
server. Run it only on a machine where that is your intended policy. Systems
with complex existing networking need their administrator's own integration.

### Firewalls and reaching the endpoint

The server listens on **UDP `51820` by default**, not TCP. A custom port in the
client endpoint (for example `vpn.example.com:443`) also sets the server listener
to that UDP port. Allow your chosen port in any provider firewall/security group.
If the server is behind a router, forward the same UDP public port to the same
port on the server. The installer prints the port it configured.

The server needs a reachable public address or a supported port-forwarding
arrangement. A home connection behind **carrier-grade NAT (CGNAT)** usually
cannot accept a simple inbound port forward. A successful local VM test does not
prove remote reachability. Ask your ISP about a public address, or use a remote
host you control. Do not expose a server's administrative ports just to run VPN.

The guided installer **refuses active UFW or firewalld** rather than changing or
bypassing that manager's policy. Keep those protections enabled. For the easiest
first test, use a fresh VM with no pre-existing firewall manager. For an existing
managed server, integrate the following through its firewall manager instead of
running this installer:

- Accept inbound UDP on the chosen port (`51820` by default).
- Accept ICMP echo requests from client `10.66.66.2` on `wg0` to server
  `10.66.66.1` if you want the documented ping diagnostic on a default-deny host.
- Permit IPv4 forwarding from `wg0`/`10.66.66.0/24` to the chosen uplink, and
  established/related return traffic.
- Masquerade only `10.66.66.0/24` on that uplink, with persistent manager-native
  configuration.
- Reject IPv6 forwarding from `wg0`; enable only IPv4 global forwarding.
- Install the validated, hook-free generated `wg0.conf` as root with mode `600`
  and enable the distribution's `wg-quick@wg0` service.

UFW and firewalld use different persistent NAT configuration. Consult your
distribution's documentation; blindly appending unrelated internet firewall
commands can leave rules ineffective or expose services. This project does not
automate that advanced deployment path.

## Verify the connection

A service saying "running" does not prove an encrypted peer connection. First
record your normal public IPv4 address in the Windows browser, then connect.

In a Windows terminal:

```powershell
ping 10.66.66.1
Resolve-DnsName example.com
curl.exe -4 --max-time 15 https://api.ipify.org
```

`10.66.66.1` is the server's private tunnel address. A reply demonstrates tunnel
reachability; an external HTTP response and DNS lookup demonstrate usable
internet routing. The public-IP query discloses your exit address to that
service, just as visiting an IP-check website would. On a remote server, the
response should match that server's public IPv4 address. In the local VM lab,
it will normally match your ordinary home public IPv4 address.

On the Linux server, after sending client traffic:

```bash
sudo wg show wg0 latest-handshakes
sudo wg show wg0 transfer
```

The client's latest-handshake timestamp must be nonzero and recent, and transfer
bytes must increase while you browse. These commands show public peer keys and
counters, not private keys. Do not use configuration-dump commands in screenshots
or support messages.

An IPv6 internet request should fail in this version:

```powershell
curl.exe -6 --max-time 10 https://api64.ipify.org
```

Disconnect and check that normal internet access returns. If the Windows app
cannot stop its tunnel service, use the WireGuard application or an elevated
terminal to stop the MyVPN tunnel, then troubleshoot before closing the app.

### If the tunnel does not work

- **No handshake:** check the endpoint, public/VM IP, UDP port, VM bridging,
  cloud/router forwarding, and that both files came from the same generated
  setup. Server startup alone cannot detect a wrong client endpoint.
- **Handshake works but no IPv4 internet:** check the selected uplink, forwarding,
  NAT rules, server DNS reachability, and any additional firewall manager. Do
  not disable the firewall wholesale.
- **DNS fails but an IP request works:** check whether the configured DNS server
  is reachable through your server. Regenerate both sides only if key changes
  are intended; editing a DNS client setting alone does not require new keys.
- **Some sites stall:** a reduced client MTU such as `1280` may help on an uplink
  with a smaller path MTU. Diagnose before changing it.
- **Service fails to start:** inspect
  `sudo journalctl -u wg-quick@wg0 --since '10 minutes ago'`. Review logs privately
  before sharing them, since network identifiers may appear.

## Stop and remove the test server

On the server:

```bash
sudo systemctl disable --now wg-quick@wg0
```

This removes the helper's tunnel rules through `PostDown` and leaves unrelated
firewall rules in place. Server configuration and keys remain on disk until you
deliberately remove them. The forwarding sysctl file also remains; do not set
forwarding globally to zero if another service relies on it. Do not delete
uploaded/generated keys until you have made any private backup you need.

## Router migration later

Tell us the router's exact model and hardware revision first. A router with
built-in WireGuard support can import a client configuration. Some models can
use OpenWrt; others cannot. Never flash firmware selected only by a similar
model name. The Windows app is not uploaded to a router: the router uses its own
WireGuard implementation and a matching configuration. Generate a **separate
peer/key pair** before using Windows and a router simultaneously; this initial
version supports one client and does not yet automate adding router peers.
