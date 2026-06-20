### Project Overview

### Current Status:
IN PROGRESS:
Many engines or verilog files have not been fully tested for functionality.

#### Snapshot
* **Project Title**: Hardware Accelerated Security System (HASS)
* **Project Name**: Click With Confidence SafeShield
* **Platform**: Xilinx Artix-7 FPGA (tentative)
* **Target Audience**: Adults 60+ in home networking environments
* **Main Concept**: Inline hardware accelerated packet scanner with real-time audiovisual feedback
* **Scope**: Wired Ethernet 802.3

#### Problem Statement
Adults over 60 are disproportionately targeted by online fraud. The FBI IC3 reports seniors lose more than $3 billion annually to internet-based scams, which is more than any other age group. The most common attack methods are tech support scam domains, phishing pages, router-based malware injection, and ARP spoofing.

Existing solutions fail this demographic in two ways:
1. Software firewalls and browser extensions require technical installation and upkeep that most users 60+ cannot manage alone.
2. Threats operate invisibly at the network layer, providing no tangible feedback that anything has gone wrong until damage is done.

HASS sits inline between the computer and the home router as a simple hardware device and makes invisible threats physically and immediately apparent through LED alerts.

---

### System Architecture

#### Overview
HASS operates as a network bridge that sits between router and user. Every packet that is retrieved by the router for the computer is analyzed by the FPGA, where hardware inspection engines analyze the packet. This does not require any software installations or drivers on the user’s computer. However, this will result in a slight drop in connectivity speed (but this is not the main priority for the target demographic) and exact drops remain to be measured.

#### Technical Architecture
* **Physical**: Two LAN8720A RMII modules with RJ45 connectors, connected through Pmod JA and Pmod JB on the Arty A7-100T.
* **MAC Layer**: Xilinx TEMAC (Tri-Mode Ethernet MAC) IP core. Handles frame encapsulation, CRC checking, and MAC-layer arbitration.
* **HDL Packet Parser**: Custom Verilog state machine. Strips Ethernet, IP, and TCP/UDP headers and passes results to the inspection.
* **Flow Tracker & Reorder Buffer**: BRAM-based flow table: 16 KB per slot, 64 concurrent flow slots. External IS62WV25616 SRAM (connected via Arduino headers) provides overflow capacity to prevent onboard BRAM being exhausted fully.
* **Parallel Inspection Engines**: Four independent HDL modules executing concurrently: Aho-Corasick signature matching, Shannon entropy calculation, DNS parser, and rate/flow monitor.

#### Packet Walkthrough
1. Inbound Ethernet jack receives a frame on Port A (user’s computer).
2. TEMAC on board checks for any corruption in the CRC portion of the frame, and corrupted frames are dropped immediately.
3. HDL parser extracts src IP, dst IP, src port, dst port, protocol, etc. and stores it in RAM.
4. Frame bytes are spread across chip to increase speed.
5. Flags are added for threat assessment, depending on thresholds packets are flagged or dropped altogether.
6. If no flags fire, the packet is forwarded to Port B without modification.
7. If a flag fires, audiovisual alerts begin.

#### Electrical Components
* **FPGA Board**: Digilent Arty A7-100T (XC7A100T)
* **PHY Chips (×2)**: LAN8720A RMII via Pmod JA and JB
* **External SRAM**: IS62WV25616 (256K × 16-bit) via Arduino headers
* **Level Shifter**: 74AHCT125 quad buffer (3.3 V → 5 V for WS2812B), on Pmod JD
* **Status LEDs**: WS2812B addressable RGB strip with frosted acrylic diffuser

#### MicroBlaze
MicroBlaze is a soft-core for Xilinx architectures that can reallocate space outside of main compute cores. This core is highly flexible and can compile tables and host HTTPS error sites to push to the user’s display. This allows the Xilinx system to effectively utilize unused system space to manage additional capabilities.

---

### Parallel Inspection Engines

All four engines run concurrently on every packet. Because the FPGA uses true hardware parallelism, total inspection latency equals the slowest single engine. This is a major advantage over software screening because a user’s computer would have to dedicate additional compute power to process this.

#### Engine One: Aho-Corasick Signature Matching
A hardware finite automaton encoding known malicious domain names as a pre-compiled state table burned into BRAM at synthesis time. DNS queries and HTTP Host headers are streamed through one byte per clock cycle, enabling O(n) matching regardless of pattern count. A threat flag fires immediately on any match.

#### Engine Two: Shannon Entropy Calculator
Computes byte-frequency entropy of each payload. Encrypted or compressed data sits near 8 bits/byte; legitimate DNS and HTTP traffic is much lower. Anomalously high entropy in flows that should be plaintext signals DNS tunneling, data exfiltration, or covert channel use. The threshold is configurable at synthesis time.

#### Engine Three: DNS Protocol Parser
A state machine that fully decodes DNS query and response packets per RFC 1035, including compressed labels.
Flags raised:
* DNS rebinding — public hostnames resolving to RFC-1918 addresses
* NXDOMAIN flooding used by malware to locate C2 servers
* Lookups matching the signature engine's known-bad domain list

#### Engine Four: Rate & Flow Monitor
Tracks per-flow packet rates and byte counts via the BRAM/SRAM flow table.
Flags raised:
* ARP spoofing via anomalous ARP reply rates
* SYN flood attempts via abnormal SYN-to-SYN-ACK ratios
* Traffic spikes consistent with automated C2 beaconing (keepalive procedure via constant pinging)

---

### Local DNS Sinkhole Browser Alert

#### Overview
The LED alert system makes threats physically apparent, but a user already focused on their screen may not notice the device at all. More critically, a senior user whose request was silently dropped may simply assume the website is slow and keep trying and may potentially find another path to the same threat. A browser-level warning fixes all of these issues.

#### Process
When any inspection engine asserts a threat flag on a DNS query, the FPGA does not simply drop the packet. Instead it:
1. Suppresses the real DNS response before it reaches the user's computer.
2. Forges a replacement DNS response mapping the requested domain to `192.168.254.1`, an IP address the device owns on the local network.
3. The user's browser, expecting a website, sends an HTTP GET to `192.168.254.1`.
4. A MicroBlaze soft-core processor instantiated in the FPGA fabric serves a locally hosted HTML warning page.
5. The user sees a clear, plain-language alert on their screen.

Redirecting to an external domain (`clickwithconfidence.org`) would be unreliable as if the device is actively blocking traffic due to a detected threat, internet reachability cannot be guaranteed. A locally hosted page sidesteps this entirely. The warning is always reachable regardless of what traffic is being blocked.

#### Compute Power Usage
The Artix-7 XC7A100T has sufficient logic fabric to instantiate a MicroBlaze soft-core processor alongside the existing inspection engine HDL without resource conflict. MicroBlaze handles only the HTTP response duty. The warning page HTML is a few kilobytes of static content stored directly in BRAM, requiring no filesystem or storage peripheral. The warning page itself is designed specifically for the target demographic.

---

### Updates Over the Internet

#### Overview
The Aho-Corasick engine's pattern table is a compiled set of known malicious domains that HASS is trained to intercept.

#### Table Sources
At any given time it contains domains drawn from three open-source, actively maintained threat intelligence feeds:
* **Abuse.ch URLhaus**: a community-driven database of malware distribution and C2 domains, exportable as a flat domain list via free API.
* **PhishTank**: a community-verified phishing domain database with a free bulk export API.
* **Emerging Threats (open ruleset)**: a widely used network security ruleset containing domain-based indicators of compromise.

#### Technical Process
At build time, a preprocessing script pulls from these feeds, filters for relevant categories, and compiles the result into a binary Aho-Corasick state table stored in the external SRAM.
* MicroBlaze runs a scheduled HTTP client task nightly during low-usage hours.
* It issues a GET request over HTTPS to a HASS update server.
* The server responds with the latest compiled binary pattern table.
* MicroBlaze verifies the integrity of the download using a CRC32 checksum sent alongside the request.
* Only if the checksum passes does MicroBlaze write the new table into the reserved SRAM region and signal the Aho-Corasick engine to swap to it.
* If the download fails, the server is unreachable, or the checksum does not match, the existing table remains in place untouched, making sure that the system remains stable.

#### Server-Side Scripts
A scheduled script running on a server does the following:
* Pulls the latest domain lists from URLhaus, PhishTank, and Emerging Threats APIs.
* Filters, deduplicates, and normalizes the combined list.
* Compiles it into a binary Aho-Corasick state table in the format expected by the FPGA.
* Hosts the compiled blob at a versioned HTTPS endpoint with a corresponding CRC32 manifest.
* Retains the previous version as a fallback.

---

### Threat Testing

| Threat | Detection Method | Engine |
| :--- | :--- | :--- |
| Tech support scam domains | Aho-Corasick on DNS/HTTP | Engine 1 |
| Phishing hostnames | Aho-Corasick on DNS/HTTP | Engine 1 |
| DNS tunneling / exfiltration | Entropy threshold on DNS payloads | Engine 2 |
| DNS rebinding attacks | RFC-1918 address in public DNS response | Engine 3 |
| ARP spoofing / MITM | ARP reply rate anomaly | Engine 4 |
| Router malware C2 beaconing | SYN anomaly and traffic spike | Engine 4 |

---

### Output States (LED)

| LED | Meaning |
| :--- | :--- |
| Green (solid) | All clear: no threats detected |
| Yellow (breathing) | Elevated suspicion: advisory alert |
| Red (flash) | Active threat: malicious pattern confirmed * |

### About Me
Hi!
My name is Viraj Shah.
I'm a rising high school junior from Cary, North Carolina.
I love photography, camping, and quite obviously, FPGAs.
This project is intended for ISEF.
© Viraj Shah 2026. All Rights Reserved.
Learn more about me [here](https://viraj-shah.vercel.app)!
