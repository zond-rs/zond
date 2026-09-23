zond for Windows
================

Requirements
------------
- Windows 10 or 11, 64-bit.
- Npcap, from https://npcap.com. zond.exe uses Npcap's wpcap.dll and does not
  start without it. The installer adds Npcap's folder to your PATH, so its
  "WinPcap API-compatible mode" is not needed.
- Windows Terminal gives the best output; the classic console works too.

Use
---
As a normal user, scans use ordinary TCP connections:

  zond d 192.168.1.0/24
  zond s <host> -p 1-1024

From an Administrator terminal, zond builds its own packets and sends them
through Npcap: ARP and ICMPv6 discovery, SYN and the other flag scans, UDP.
Whatever a frame cannot reach (loopback, this machine's own addresses, targets
behind a VPN tunnel) is reached by connection instead; -v shows which.

zond --help lists everything else. Scan only networks you may scan.
