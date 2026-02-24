# lannew Project Memory

## Project Structure
- Pico (rp2040/rp2350) ethernet project using `lan8720` PHY + `lneto` TCP/IP stack + PIO
- Examples in `examples/pico-http-server/`
- lneto source lives at `/home/pato/Documents/src/tg/lneto/`
- Stack: `lannet.Stack` wraps lneto, provides DHCP/DNS/NTP helpers via `xnet`

## Analyzing Packet Capture Logs
The `.out` files are serial output from the pico with pcap-style packet dumps. Key patterns for analysis:

### Log format
- `NNNN.NNN RX/TX<len>` — timestamp (seconds since boot), direction, frame length
- Layers decoded inline: `Ethernet | IPv4 | TCP | HTTP`
- `time=... level=ERROR msg=RecvAndSend:Demux plen=N err="..."` — stack-level errors
- Application prints like `incoming connection:`, `Got webpage request!`, `read error:` appear inline between packet dumps

### Analysis approach
1. **Filter first**: grep for `incoming connection|Got webpage|toggle led|tcpListener|read error|BAD TCP|ERROR RX` to get the event skeleton
2. **Identify actors by IP+port**: Track each TCP connection as a (src_ip, src_port, dst_port) tuple through SYN→data→FIN
3. **Distinguish users by User-Agent**: Desktop vs mobile Chrome appears in HTTP headers within the hex dump or decoded section
4. **TTL fingerprinting**: TTL=63 (0x3f) = 1 hop through local router (WiFi/LAN), TTL=55 (0x37) = mobile data with more hops. MSS=1460 = ethernet, MSS=1380 = mobile data
5. **Trace connection lifecycle**: SYN → SYN-ACK → ACK → data → FIN sequence. Look for where it breaks
6. **Check for silent drops**: "packet dropped" on TCP SYNs means the remote gets no response and will retry with exponential backoff. This is the worst failure mode
7. **Check port 443 SYNs**: Modern browsers try HTTPS first. Silent drops on 443 = long delay before HTTP fallback

### Known issues (as of 2026-02-23)
- lneto silently drops packets instead of sending RST in 3 cases: no listener on port, pool full, closed connection
- `handleConn` now has 10s read deadline + error check (was missing error check, causing hot spin loop)
- `maxConns` bumped from 3 to 10
- REPORT.md in examples/pico-http-server/ has full analysis and RST implementation plan

## User Preferences
- User is "pato", comfortable with low-level networking and Go
- lneto is their own TCP/IP stack — they make changes there directly
