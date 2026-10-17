# S33/S33v2 optimization and security evidence

Researched 2026-10-16 against primary documentation. The user identified the ISP as Comcast/Xfinity and the router as GL.iNet Flint 2 (GL-MT6000). No modem access, credential reads, configuration changes, or vulnerability probes were performed for this research. The subscribed download/upload tier, address-specific enhanced-upload availability, router firmware/configuration, and negotiated Ethernet rate remain unverified.

## Measured baseline

The parent task inspected existing local samples; this research did not open the captures or password file. The latest saved sample, 2026-10-16 at 09:28 America/Los_Angeles, reports Connected/Allowed, all 34 downstream and four upstream channels locked, and uptime 324,650 seconds. The 32 QAM256 channels show 0 to +2 dBmV power and 42–44 dB SNR, comfortably satisfying the published QAM guidance below. Four upstream SC-QAM channels show 48.8–50.0 dBmV: within the published 45–51 range, near its upper end. The two OFDM PLC channels report 0/-2 dBmV and 41/40 dB, without an applicable OFDM limit in the cited ARRIS table.

Across the preceding 48,987 uptime seconds (13.607 hours), the uptime increase agrees with capture timestamps within approximately 0.23 seconds, consistent with no reset between those observations; this is not continuous proof of stability. All 32 QAM channels' corrected and uncorrectable counters are unchanged. The two OFDM channels combined add 1,304,912,257 corrected codewords and 27 uncorrectable codewords. Those totals do not establish equivalent packet loss or justify changing RF hardware. The snapshots contain no speed or latency benchmark. These observations support keeping the functioning modem configuration while investigating any specific symptoms.

The password file is Git-ignored and has mode `600`; its contents were not read. The collector's session factory currently disables TLS certificate verification (`session.verify = False` in `http_compatibility.py`). HTTPS peer identity therefore has not been verified by this tooling. A supported HTTPS mode with certificate validation or explicit certificate pinning would be a future collector security improvement.

## What can be changed

The S33 is a cable modem; it lacks Wi-Fi, router functions, parental controls, and port forwarding. Its Ethernet interfaces are one 2.5 Gb/s port and one 1 Gb/s port. A typical installation connects one router, which supplies the home-network functions. A second Internet-connected device requires another ISP-provided IP address, where offered. [ARRIS: Ethernet ports](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/S33-Ethernet-Ports)

There is no link aggregation: connecting both modem ports cannot combine their bandwidth. For a service faster than 1 Gb/s, check that the router uses the modem's 2.5 Gb/s port and can negotiate 2.5 Gb/s on its WAN port. Cable/port changes need a maintenance window if the connection is in use. [ARRIS: Link aggregation support](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/S33-Link-Aggregation-LAC-Support)

ARRIS develops modem firmware, but the cable provider qualifies and distributes it. Owners cannot install updates in the usual router-style manner. Ask the ISP whether the previously observed `TB01.03.001.11_051722_212.S3` is its current approved S33v2 build and whether provisioning matches the subscribed tier. The version string's age alone establishes neither vulnerability nor an available update. [ARRIS: Firmware updates](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/Upgrading-Firmware-on-Cable-Devices)

## Signal guidance and limits

ARRIS publishes the following **acceptable ranges**, not universal tuning targets:

| Channel type | Published guidance |
| --- | --- |
| Downstream power | -15 to +15 dBmV |
| QAM64 downstream SNR | At least 23.5 dB |
| QAM256 SNR, power -6 to +15 dBmV | At least 30 dB |
| QAM256 SNR, power -15 to -6 dBmV | At least 33 dB |
| One SC-QAM upstream | 45 to 61 dBmV |
| Two SC-QAM upstream channels | 45 to 54 dBmV |
| Three or more SC-QAM upstream channels | 45 to 51 dBmV |

The article recommends repeated measurements and ISP assistance for signal adjustment. It does **not** provide equivalent OFDM/OFDMA thresholds; do not apply its QAM256 limits indiscriminately to DOCSIS 3.1 channels. These broad ranges alone cannot establish throughput or service reliability. [ARRIS: Cable signal levels](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/S33-Cable-Signal-Levels)

Use measured trends, channel-lock changes, event timing, uptime, and actual user-visible loss/latency to decide whether there is a problem. Corrected codewords are not a direct packet-loss measurement; cumulative counters need interval differences and reset detection. A blanket zero-error target or an amplifier/attenuator recommendation is not justified by the documentation reviewed.

Check accessible coax connectors for a secure hand-tight connection and use the supplied power adapter. ARRIS warns that an incorrect adapter can impair operation and firmware updates. Its troubleshooting page includes power cycling and factory resetting, but these are disruptive troubleshooting steps, not routine optimization. [ARRIS: Connection troubleshooting](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/S33-Troubleshooting-Internet-Connection)

Keep airflow unobstructed, avoid excessive heat/dust, and keep ambient temperature at or below 40 °C / 104 °F. The manual advises a surge protector and says not to open the enclosure. This supports checking placement; it does not establish a need for a fan or hardware modification. [ARRIS S33 user guide, pp. 3–5, hosted by Midco](https://midco.com/globalassets/support-new/internet/modems/approved-modems/s33-manual.pdf)

## Security actions

Use a unique modem administrator password and retain it in a password manager. ARRIS documents password changes under Login Settings, with firmware-dependent requirements; its current page lists 8–16 characters, uppercase/lowercase, a number, and a permitted special character. Tooling preserves literal input, but the modem's own accepted-character rules still apply. Repeated failed logins can produce a ten-minute lockout. [ARRIS: Web Manager access](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/S33-Web-Manager-Access)

Engineering recommendations for the identified Flint 2: allow modem administration only from trusted management devices; prevent guest/IoT networks from reaching `192.168.100.1`; keep the router's firewall and software current; review WAN remote administration and unnecessary port forwards/UPnP. These are router controls, not settings supplied by this modem. Do not expose a collector, dashboard, or modem administration interface to the public Internet to enable monitoring. The FTC recommends router updates, a firewall, guest networking, and disabling remote administration, WPS, and UPnP. [FTC: Home Wi-Fi security](https://consumer.ftc.gov/articles/how-secure-your-home-wi-fi-network)

Protect `modem_pass` and collected snapshots with owner-only permissions. The current client constructs HTTPS URLs, but disables certificate verification. HNAP password signing should not be mistaken for authenticated TLS: the collector needs certificate validation or explicit certificate pinning to verify the server's identity. No TLS transport or security setting was changed here.

No exact S33/S33v2 vulnerability applicability was established by the official sources reviewed. This is not a security audit or a claim that no vulnerability exists.

## Monitoring without adding load

The repository's finite monitor enforces at least 900 seconds between samples, uses serial requests and zero retries, and stops on incomplete data. `--channels-only` batches both channel tables into one status request; the client reuses its authenticated session. These are conservative project choices, not a manufacturer-certified safe polling rate. Inspect [monitor.py](../arris_modem_status/cli/monitor.py) and the [README](../README.md). Run one collector and avoid repeatedly restarting after an authentication failure. Never automatically reboot or factory-reset the modem in response to a single sample.

A useful next step is a read-only baseline during ordinary usage, followed by ISP/router-specific changes only where evidence identifies a bottleneck or exposure. Confirm plan speed, Ethernet WAN rate, router configuration, and symptoms before recommending purchases or configuration changes.

## Comcast/Xfinity compatibility and upload limits

Xfinity's current support instructions direct customers to sign in to **My Device Info** for personalized device compatibility, or enter their service address. Check the exact **S33v2** hardware revision against the subscribed download **and upload** tier and local enhanced-upload availability. General DOCSIS 3.1 support or a gigabit download rating does not establish eligibility for enhanced uploads. No account/address lookup was performed here. [Xfinity: Using your own equipment](https://www.xfinity.com/support/articles/list-of-approved-cable-modems), [My Device Info](https://www.xfinity.com/support/internet/customerowned)

The official PDF retrieved during this research is explicitly dated **March 26, 2025**, despite being accessible today. It lists S33 as recommended for wired downloads up to 2.33 Gb/s and **S33v2 separately** as compatible up to 2.32 Gb/s. Neither appears in that document's **Next Gen Speed Tier** section; S34 does. These are historical certification/rating entries, not promised subscriber speeds or proof of current address-specific eligibility. The live device app requires JavaScript and its personalized results were not independently verified. Do not use an older 2023 PDF or generic “recommended” label to promise faster uploads. [Xfinity: March 2025 device list](https://assets.xfinity.com/assets/dotcom/projects/cix-4997_compatible-devices/2025.03.25%20Full%20List%20of%20Compatible%20Devices.pdf)

First verify plan details in the Xfinity account and compare a wired speed test with those entitlements. If measured upload is below the tier this exact modem is certified to receive at this address, ask Xfinity to verify the registered model/revision, provisioning/service profile, and approved firmware. There is no evidenced local modem setting that enables an unapproved enhanced-upload tier; the ISP firmware distribution boundary above still applies. If replacement is actually required, choose from the current signed-in/address-specific enhanced-speed list only after confirming need.

Xfinity documents app-based activation for approved customer-owned modems. Activation or reprovisioning may interrupt service; do not re-run activation, factory-reset the working modem, change identifiers, or flash firmware merely to test an upload hypothesis. [Xfinity: Activate an approved third-party modem](https://www.xfinity.com/support/articles/activate-xfi-gateway-app)


## Flint 2 settings to review

The router is GL.iNet Flint 2 (GL-MT6000). The installed firmware and current
configuration have not been inspected. GL.iNet's interface changes between
releases; the paths below are documented choices rather than a report of settings
already present on this router.

1. **Firmware:** open System → Upgrade, record the version, back up the
   configuration, and review the offered official stable update. Leave Accept
   Preview Plan disabled for a reliability-first installation. Upgrades reboot the
   router and need an appropriate maintenance window. The documented Modem Upgrade
   function is for cellular modules, not the attached ARRIS cable modem.
   [GL.iNet: Upgrade](https://docs.gl-inet.com/router/en/4/interface_guide/upgrade/)
2. **WAN link:** connect S33 2.5GE to the Flint 2's 2.5G WAN port and verify the
   negotiated rate in Network → Ethernet Port / Port Management (firmware v4.7–4.9).
   Prefer automatic negotiation; a low negotiated rate calls for checking the
   selected port and cable. The client-side Ethernet/Wi-Fi link must also support
   the speed being tested. Do not connect both S33 ports for aggregation.
   [GL.iNet: Ethernet Port](https://docs.gl-inet.com/router/en/4/interface_guide/ethernet_port/)
3. **Administration:** enable Force HTTPS, retain a short idle logout such as five
   minutes, disable WAN HTTPS and SSH administration when not required, and disable
   local SSH only if it is unused. The menu is Security → Admin Access on v4.9+,
   or System → Security on older supported releases. Review remote access tools
   such as GoodCloud separately if enabled. These are recommended target settings;
   no current exposure was established.
   [GL.iNet: Admin Access](https://docs.gl-inet.com/router/en/4/interface_guide/admin_access/),
   [older Security page](https://docs.gl-inet.com/router/en/4/interface_guide/security/)
4. **Guest/IoT separation:** use Network → Guest Network for untrusted devices.
   AP Isolation separates guest clients, and Block WAN Subnets is available from
   v4.8. Verify separately that the guest network cannot reach the modem at
   192.168.100.1: it is on the WAN side and may not share the WAN's assigned
   subnet, so LAN or AP isolation alone is not proof of protection. If still
   reachable, use an explicit guest-to-modem deny rule while preserving trusted
   collector access. That rule needs the actual zone/configuration reviewed first.
   [GL.iNet: Guest Network](https://docs.gl-inet.com/router/en/4/interface_guide/guest_network/)
5. **Exposure:** keep DMZ disabled unless there is a reviewed reason, and remove
   unused port forwards. Review UPnP and remote management against actual needs;
   disabling an actively used service may affect applications. Do not forward
   router, modem, or collector administration to the public Internet.
   [GL.iNet: Port Forwarding](https://docs.gl-inet.com/router/en/4/interface_guide/port_forwarding/)

### Choose latency or throughput based on measurements

First establish a wired baseline of download, upload, and idle/loaded latency.
If a VPN is used, label VPN and direct-ISP results separately; do not use a VPN
bottleneck as the estimate of raw Comcast capacity.

- For latency spikes during heavy transfers, trial SQM. GL.iNet's stock interface
  is documented from v4.9 under Flow Control → SQM. It supports Flint 2, disables
  Network Acceleration, and may reduce maximum throughput. SQM and the separate
  QoS feature cannot operate together.
- For maximum throughput where loaded latency is already acceptable, retain
  Network Acceleration and omit SQM. Acceleration also conflicts with some client
  statistics and speed-limit features.

[GL.iNet: SQM](https://docs.gl-inet.com/router/en/4/interface_guide/sqm/),
[Network Acceleration](https://docs.gl-inet.com/router/en/4/interface_guide/network_acceleration/)

For an SQM trial, about 90% of repeatably measured wired download/upload speeds is
an OpenWrt-documented starting point, followed by a repeat loaded-latency test and
adjustment. This is a tuning starting point, not a fixed requirement or a promise
that Flint 2 can shape every multi-gigabit plan at full speed. No numeric bandwidth
limits are chosen yet because the user's plan and measured rates are unknown.
[OpenWrt: SQM setup](https://openwrt.org/docs/guide-user/network/traffic-shaping/sqm)
