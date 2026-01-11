DMEye Forensic Tool is a commercial Windows security utility designed to detect, identify, and report
potential Direct Memory Access (DMA) device attacks or cheating hardware on any modern PC. Built for
enterprises, system administrators, and gaming professionals, DMEye provides robust forensic insights
and proactively warns users of system vulnerabilities and suspicious hardware.

Key Features
--------------------------------
Advanced DMA Device Detection: Scans for PCI/PCIe devices and cross-checks against known
cheat device vendor IDs and keyword lists.

Comprehensive Hardware Audit: Locates suspicious and hidden PCI devices using both standard
and deep system enumeration.

Registry & Log Analysis: Reviews key Windows registry locations and the SetupAPI log for
evidence of unusual or potentially malicious hardware change events.

Security Configuration Checker: Audits the system for Secure Boot, Kernel DMA Protection, Core
Isolation, Defender Real-Time Protection, and Tamper Protection status.

Professional Forensic Reports: Exports results in JSON, HTML, or TXT formats. Optional realtime reporting via Discord webhook integration.
Visual Risk Scoring: Color-coded traffic-light scoring (Green = Safe, Yellow = Vulnerable, Red =
Definite Risk/Evidence).

Why DMA Security Matters?
---------------------------
DMA-capable devices can access system memory directly, bypassing operating system controls. While
legitimate DMA is used by high-speed peripherals, it is also leveraged by sophisticated attackers and
cheaters to read/write memory undetected, including:
- Game cheats (unfair competition)
- Data exfiltration (corporate espionage)
- Ransomware and kernel-level malware

Use Cases
----------------------
- Corporate IT Forensics: Investigate endpoints for unauthorized DMA adapter activity or rogue
peripherals.
- Gaming Security Teams: Identify hardware-based cheating in tournaments or eSports venues.
Incident Response: Validate or disprove DMA-based attack vectors during breach analysis.
- Routine Auditing: Periodically validate endpoint security posture and DMA risk factors.

Supported Platforms
---------------------
Windows 10, 11, and Windows Server 2016+ (some functions require Administrator privileges)
Works with both legacy BIOS and UEFI/modern Secure Boot systems
