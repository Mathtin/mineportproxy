# mineportproxy

Want to make "Open to LAN" in minecraft bind to default 25565 port? You can't but you can setup port forwarding rules or just use my app which will manage that for you.


## Run

### Windows

1. Download `mineportproxy-windows.zip` from <a href="https://github.com/Mathtin/mineportproxy/releases">Releases</a> section
2. Unpack downloaded zip-file
2. Start `mineportproxy.exe` (will ask for admin priveleges)

### Linux

1. Download `mineportproxy-linux.tar.xz` from <a href="https://github.com/Mathtin/mineportproxy/releases">Releases</a> section
2. Unpack downloaded archive `tar -xf mineportproxy-linux.tar.xz`
2. Start `sudo ./mineportproxy/mineportproxy`


## Description

**`mineportproxy`** is a python script which tracks started Minecraft instances and listening ports associated with them. If found listening port (supposed lan world started), it will push forwarding rules using netsh on windows and iptables on linux to forward incoming traffic from static port range (port pool) to detected one. Script will drop rules for stopped worlds (if no listening ports detected).


## Build

### Windows

Run `build.bat`. Result will be stored in `dist-win` directory.

### Linux

Run `sh build.sh`. Result will be stored in `dist-lin` directory.


## Ports Arguments

**`mineportproxy`** accepts two arguments: port_start (default: 25565) and port_end (default: port_start). These arguments define port range which will be used to forward traffic with multiple world instances. For example:

```no-highligh
$ sudo ./mineportproxy 25565 25566
```

Also, one starts three lan worlds on random ports 4399, 8775 and 34665. Script will detect world on port 4399 and bind it on 25565, then it will detect another one on 8775 and bind on 25566. It will also detect third world on 34665 on each check cycle but will do nothing until any of previous worlds would stop (error not enough ports will pop up in logs).


## Requirements

For Linux:

* kernel with NAT support (should be)
* forwarding enabled (`echo "1" > /proc/sys/net/ipv4/ip_forward`)
* iptables (root)
* iptables-save (root)
* netstat (root)

For Windows:

* 7 or higher
* admin privileges (for netsh)


## Licence

MIT licence


## Author

* Daniil `Mathtin` Shigapov me@matht.in
