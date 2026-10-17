# FAQ

## Does MapIp tell me where an IP address is located?

No. MapIp maps the hosts on your own network. It does not geolocate IP
addresses and does not report country, city, region or ISP. It has no
third-party IP-to-location lookup and makes no outbound requests other than
the probes you ask it to send to your own hosts.

## Does MapIp phone home?

No. There is no telemetry, no analytics, no update check. The only network
traffic MapIp generates is the discovery and port probes you request against
your own targets.

## Does the OUI database need a network connection?

No. The IEEE OUI registry (46,000+ prefixes) is embedded in the binary. No
download happens at runtime.

## Can I scan a network I do not own?

You should not. MapIp is designed for your own network. Scanning networks you
do not own or have permission to test may be illegal in your jurisdiction.

## Why is the vendor column empty for some devices?

The vendor is derived from the MAC address via the IEEE OUI registry. Some
devices use locally administered or randomized MAC addresses (for example
many phones and modern laptops), which have no registered vendor. That is
expected and not an error.

## What is the difference between MapIp and Nmap?

Nmap is a raw-packet scanner with OS detection, scripting and a huge
feature set, and it requires elevated privileges for most of its modes.
MapIp is a host inventory and monitoring tool that works without elevation on
Windows, ships as one self-contained binary, and adds continuous change
detection and a desktop GUI. For deep packet-level scanning, use Nmap; for
day-to-day LAN inventory, use MapIp. MapIp's XML output is Nmap-compatible
so the two tools compose.

## Where is scan history stored?

In `~/.mapip/snapshots/` as JSON. Each scan writes one file. The `mapip`
CLI and the desktop app share this directory.

## How do I run the desktop app against a remote core?

Start `mapip serve --addr 0.0.0.0:8765` on the target machine and point the
desktop app at it. By default the desktop app spawns a local core.
