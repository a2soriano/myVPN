# Validation and remaining acceptance checks

Development happened in a Linux cloud container, not on your Windows computer.
The source targets built-in **Windows PowerShell 5.1** and Windows Forms.

## Automated checks run here

- Parse every PowerShell source/test file with PowerShell 7.4.6.
- Execute configuration-generation tests with fixture keys and a filesystem
  permission test double, including injection rejection, matching custom ports,
  full/split routes, non-secret metadata, UTF-8 output, and overwrite refusal.
- Execute controller validation tests for imported profiles, handshake
  interpretation, foreign-service protection, and mocked service transitions.
- Parse Linux scripts with `bash -n` and execute server tests with firewall
  test doubles. No real firewall or network interface changes are made.
- Build and inspect the ZIP for source files only, excluding key/profile files.

Passing logic checks **does not prove a live VPN connection**. PowerShell 7
parsing also does not establish Windows PowerShell 5.1 runtime compatibility.
The downloaded test PowerShell runtime was verified against the official
release's SHA-256 checksum.

## Run on your Windows PC

1. Install official WireGuard, extract the project, and run `tests/Test-All.ps1`.
2. Run `tests/Test-Windows.ps1`. It uses actual `wg.exe` to generate temporary
   keys, checks that both peer key pairs match, and checks NTFS access rules.
   It deletes only its temporary folder and never starts a VPN.
3. Launch `MyVPN.cmd`. Check the UAC prompt, first-run instructions, creation
   dialog, imported profile, and setup-folder button.
4. Follow `docs/server.md` to deploy to your Ubuntu VM/server. Complete the ping,
   recent-handshake, DNS, IPv4 HTTP, exit-IP, and blocked-IPv6 checks.
5. Disconnect and verify normal internet returns. Reconnect, close the app,
   reopen it, and verify it still reports the owned tunnel and can disconnect.
6. Confirm another WireGuard tunnel is left unchanged. Do not simultaneously
   run two full-tunnel VPNs during the first experiment.

The Windows GUI, actual Windows service/driver behavior, NTFS enforcement, Linux
privileged installation, and an end-to-end connection have **not** been executed
in this cloud development environment. No server has been deployed for you, and
no router firmware has been changed.
