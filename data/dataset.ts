
import { Scenario } from '../types';

export const scenarios: Scenario[] = [
  // --- DOMAIN 1: GENERAL SECURITY CONCEPTS ---
  {
    id: 'GSC-001',
    domain: 'General Security Concepts',
    question: 'A security analyst observes a successful login from the CEO’s account in London at 3:00 AM, followed by another successful login from New York at 3:15 AM. Which concept describes this indicator of compromise?',
    options: ['Impossible Travel', 'Time-of-day Restriction', 'Geofencing', 'Conditional Access'],
    correctIndex: 0,
    explanation: 'Impossible Travel (or concurrent login) detects geographically distant logins occurring within a timeframe physically impossible for a single user to travel.',
    rationales: [
      'CORRECT: Impossible Travel calculates the velocity between two login locations. London to NY in 15 minutes implies a speed > 13,000 mph, triggering the alert.',
      'INCORRECT: Time-of-day restrictions prevent logins during specific hours, but do not analyze geographic distance or velocity.',
      'INCORRECT: Geofencing creates a virtual boundary to allow/deny access based on location, but does not necessarily compare two simultaneous valid logins.',
      'INCORRECT: Conditional Access is the policy enforcement engine (the "how"), whereas Impossible Travel is the behavioral signal (the "what").'
    ],
    objectiveCodes: ['2.4', '4.4'],
    tags: ['Behavioral Analytics', 'Identity', 'Monitoring'],
    threatLevel: 'high',
    logs: ['AUTH_LOG: User "CEO" login Success [London, UK] 03:00:00', 'AUTH_LOG: User "CEO" login Success [New York, USA] 03:15:00', 'SIEM_ALERT: Velocity violation detected'],
    refs: [{ source: 'Study Guide', section: '2.4 - Indicators of Compromise' }]
  },
  {
    id: 'GSC-002',
    domain: 'General Security Concepts',
    question: 'Which cryptographic concept ensures that a sender cannot deny having sent a message?',
    options: ['Confidentiality', 'Non-repudiation', 'Obfuscation', 'Availability'],
    correctIndex: 1,
    explanation: 'Non-repudiation provides proof of the origin of data and the integrity of the data, usually via digital signatures.',
    rationales: [
      'INCORRECT: Confidentiality ensures data is only viewable by authorized parties (usually via encryption), but does not prove who sent it.',
      'CORRECT: Non-repudiation uses a user\'s private key to sign a message. Since only they have the private key, they cannot deny sending it.',
      'INCORRECT: Obfuscation makes data difficult to understand (like masking or steganography) but provides no proof of origin.',
      'INCORRECT: Availability ensures systems are up and running, unrelated to sender verification.'
    ],
    objectiveCodes: ['1.2', '1.4'],
    tags: ['Cryptography', 'PKI', 'Digital Signatures'],
    threatLevel: 'low',
    logs: ['MAIL_GW: Signature verified', 'PKI_AUDIT: Sender identity confirmed via Private Key'],
    refs: [{ source: 'Study Guide', section: '1.2 - Non-repudiation' }]
  },
  {
    id: 'GSC-003',
    domain: 'General Security Concepts',
    question: 'A manufacturing company wants to implement a control that physically prevents vehicles from crashing into the front entrance of their data center. What is the BEST choice?',
    options: ['Motion Sensors', 'Bollards', 'Air Gap', 'Faraday Cage'],
    correctIndex: 1,
    explanation: 'Bollards are heavy vertical posts designed to stop vehicles while allowing pedestrian traffic.',
    rationales: [
      'INCORRECT: Motion sensors are a detective control. They can alert you to a vehicle, but they cannot physically stop it.',
      'CORRECT: Bollards are a preventive physical control specifically engineered to stop kinetic force (vehicles) from breaching a perimeter.',
      'INCORRECT: An Air Gap is a network security control that physically separates networks. It stops packets, not trucks.',
      'INCORRECT: A Faraday Cage blocks electromagnetic signals (radio waves), not physical vehicles.'
    ],
    objectiveCodes: ['1.2'],
    tags: ['Physical Security', 'Controls'],
    threatLevel: 'low',
    logs: ['FACILITY_LOG: Vehicle impact detected at Perimeter Gate 1', 'SECURITY_CAM: Truck stopped by physical barrier'],
    refs: [{ source: 'Study Guide', section: '1.2 - Physical Security' }]
  },
  {
    id: 'TVM-003',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker inputs "\' OR 1=1; --" into a website login field and gains administrative access. What type of attack is this?',
    options: ['XSS', 'SQL Injection', 'CSRF', 'Buffer Overflow'],
    correctIndex: 1,
    explanation: 'SQL Injection (SQLi) involves injecting malicious SQL commands into input fields to manipulate the backend database.',
    rationales: [
      'INCORRECT: XSS (Cross-Site Scripting) injects client-side scripts (like JavaScript) into web pages viewed by other users. It targets the user, not the database.',
      'CORRECT: The payload "\' OR 1=1" is a classic tautology that forces a database query to evaluate as true, bypassing authentication checks.',
      'INCORRECT: CSRF (Cross-Site Request Forgery) tricks a user into executing unwanted actions on a web application where they are authenticated.',
      'INCORRECT: Buffer Overflow involves sending too much data to a memory buffer to crash the system or execute code. It does not typically use SQL syntax.'
    ],
    objectiveCodes: ['2.3', '4.1'],
    tags: ['Application Attacks', 'Database', 'Injection'],
    threatLevel: 'critical',
    logs: ['DB_QUERY: SELECT * FROM users WHERE user = \'admin\' OR 1=1', 'WAF_BLOCK: SQL keyword detected in POST body'],
    refs: [{ source: 'Study Guide', section: '2.3 - SQL Injection' }]
  },
  {
    id: 'TVM-007',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which type of malware disguises itself as legitimate software to trick the user into installing it?',
    options: ['Worm', 'Trojan', 'Virus', 'Logic Bomb'],
    correctIndex: 1,
    explanation: 'A Trojan Horse (Trojan) pretends to be beneficial software but contains a malicious payload.',
    rationales: [
      'INCORRECT: A Worm self-replicates across a network without user interaction. It does not need to disguise itself as a program to trick a user.',
      'CORRECT: Like the wooden horse of Troy, a Trojan appears useful (e.g., a free game) to trick the user into installing it, delivering a hidden payload.',
      'INCORRECT: A Virus needs a host file to infect and requires user action to spread, but "disguise" is the primary characteristic of a Trojan.',
      'INCORRECT: A Logic Bomb is malicious code inserted into a program that lies dormant until specific conditions are met.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['Malware', 'Social Engineering'],
    threatLevel: 'high',
    logs: ['ENDPOINT_AV: "FreeScreensaver.exe" detected as Trojan.Win32.Generic', 'SYS_EVENT: Unexpected outbound connection from new process'],
    refs: [{ source: 'Study Guide', section: '2.4 - An Overview of Malware' }]
  },
  {
    id: 'ARC-005',
    domain: 'Security Architecture',
    question: 'Which architecture model assumes that no user or device should be trusted by default, even if they are inside the corporate network?',
    options: ['Defense in Depth', 'Zero Trust', 'Perimeter Security', 'Air Gapped'],
    correctIndex: 1,
    explanation: 'Zero Trust architecture operates on the principle of "never trust, always verify."',
    rationales: [
      'INCORRECT: Defense in Depth uses layered security controls but traditionally assumes some level of trust for internal zones.',
      'CORRECT: Zero Trust eliminates the concept of a trusted internal network. Every access request is fully authenticated, authorized, and encrypted.',
      'INCORRECT: Perimeter Security focuses on hardening the edge (firewall) and assumes things inside are relatively safe (the "hard shell, soft center" model).',
      'INCORRECT: Air Gapped is a physical isolation strategy, not a holistic architecture model for connected users.'
    ],
    objectiveCodes: ['1.2', '3.1'],
    tags: ['Architecture', 'Zero Trust', 'Cloud'],
    threatLevel: 'medium',
    logs: ['ZTA_GATEWAY: User authenticated but device health check failed', 'ACCESS_DENIED: Resource "HR_Data" blocked due to low trust score'],
    refs: [{ source: 'Study Guide', section: '1.2 - Zero Trust' }]
  },
  {
    id: 'OPS-002',
    domain: 'Security Operations',
    question: 'Which tool would a security analyst use to capture and analyze network traffic in real-time to troubleshoot a connectivity issue or investigate a breach?',
    options: ['Nmap', 'Wireshark', 'Netcat', 'Hashcat'],
    correctIndex: 1,
    explanation: 'Wireshark is a protocol analyzer (packet sniffer) used to capture and inspect data packets flowing over a network.',
    rationales: [
      'INCORRECT: Nmap is a network scanner used for discovery and vulnerability scanning, not deep packet inspection.',
      'CORRECT: Wireshark captures raw pcap data, allowing analysts to reconstruct streams and see exactly what happened on the wire.',
      'INCORRECT: Netcat is a networking utility for reading/writing to network connections (a "Swiss Army knife"), not primarily for analysis.',
      'INCORRECT: Hashcat is a password recovery tool used for cracking hashes.'
    ],
    objectiveCodes: ['4.4', '4.8'],
    tags: ['Tools', 'Forensics', 'Network'],
    threatLevel: 'low',
    logs: ['PACKET_CAP: PCAP file saved', 'ANALYSIS: Discovered cleartext password in FTP stream'],
    refs: [{ source: 'Study Guide', section: '4.4 - Security Tools' }]
  },
  {
    id: 'GRC-002',
    domain: 'Governance, Risk, Compliance',
    question: 'Which regulation specifically protects the privacy of personal data for European Union citizens?',
    options: ['NIST', 'GDPR', 'ISO 27001', 'FERPA'],
    correctIndex: 1,
    explanation: 'GDPR (General Data Protection Regulation) is the EU regulation on data protection and privacy.',
    rationales: [
      'INCORRECT: NIST is a US government agency that provides standards and frameworks (like RMF), not a privacy law.',
      'CORRECT: GDPR mandates strict controls over EU citizen data, including the "right to be forgotten" and high fines for non-compliance.',
      'INCORRECT: ISO 27001 is an international standard for information security management systems, not a specific privacy law.',
      'INCORRECT: FERPA is a US federal law protecting student education records.'
    ],
    objectiveCodes: ['5.4', '3.3'],
    tags: ['Compliance', 'Regulations', 'Privacy'],
    threatLevel: 'high',
    logs: ['PRIVACY_REQ: "Right to be forgotten" request received', 'DB_ADMIN: Purging user records for EU citizen ID 4492'],
    refs: [{ source: 'Study Guide', section: '5.4 - Privacy' }]
  },
  {
    id: 'TVM-009',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which attack involves an attacker sending thousands of SYN packets to a server with a spoofed IP address, attempting to exhaust the server’s resources?',
    options: ['SYN Flood', 'Ping of Death', 'DNS Amplification', 'ARP Poisoning'],
    correctIndex: 0,
    explanation: 'A SYN Flood is a DoS attack where the attacker initiates the TCP handshake (SYN) but never completes it (ACK), filling the server\'s state table.',
    rationales: [
      'CORRECT: The server waits for the final ACK that never comes. This consumes memory (half-open connections) until the server crashes or blocks legitimate traffic.',
      'INCORRECT: Ping of Death involves sending malformed or oversized ICMP packets to crash a system, not SYN packets.',
      'INCORRECT: DNS Amplification uses public DNS servers to flood a target with UDP traffic, not TCP SYN packets.',
      'INCORRECT: ARP Poisoning corrupts the ARP cache on a local network to intercept traffic (On-path attack), not to exhaust server resources directly.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['DoS', 'Network Attacks', 'Protocol Abuse'],
    threatLevel: 'critical',
    logs: ['FW_ALERT: High rate of half-open TCP connections', 'SERVER_LOG: Unable to allocate memory for new socket'],
    refs: [{ source: 'Study Guide', section: '2.4 - Denial of Service' }]
  },
  {
    id: 'ARC-006',
    domain: 'Security Architecture',
    question: 'A company needs to ensure that critical industrial control systems (ICS) are completely isolated from the internet and the corporate network. Which strategy should be used?',
    options: ['Air Gap', 'DMZ', 'VPN', 'VLAN'],
    correctIndex: 0,
    explanation: 'An Air Gap is a physical security measure that ensures a secure network is physically isolated from unsecured networks.',
    rationales: [
      'CORRECT: Air gapping means there is no physical or logical connection to the outside world. It is the gold standard for high-security ICS/SCADA systems.',
      'INCORRECT: A DMZ is designed to expose services to the internet securely. ICS systems should NOT be exposed.',
      'INCORRECT: A VPN connects networks over the internet. It provides encryption, but creates a pathway that could potentially be exploited.',
      'INCORRECT: A VLAN provides logical segmentation on the same physical hardware. It is not as secure as physical isolation (air gap) against sophisticated attacks.'
    ],
    objectiveCodes: ['2.5', '3.1'],
    tags: ['ICS/SCADA', 'Network Segmentation', 'Physical Security'],
    threatLevel: 'high',
    logs: ['NETWORK_AUDIT: No physical path found between ICS and Corp LAN', 'PHYSICAL_INSPECT: Visual confirmation of air gap'],
    refs: [{ source: 'Study Guide', section: '3.1 - Network Infrastructure Concepts' }]
  },
  {
    id: 'OPS-003',
    domain: 'Security Operations',
    question: 'During a forensic investigation, which of the following must be documented to prove that evidence has been handled securely and has not been tampered with?',
    options: ['Chain of Custody', 'Incident Report', 'Root Cause Analysis', 'SLA'],
    correctIndex: 0,
    explanation: 'The Chain of Custody is a chronological documentation trail that records the sequence of custody, control, transfer, analysis, and disposition of evidence.',
    rationales: [
      'CORRECT: Without a unbroken Chain of Custody, evidence can be dismissed in court because its integrity cannot be proven.',
      'INCORRECT: An Incident Report summarizes the event but does not track the specific handling of evidence pieces.',
      'INCORRECT: Root Cause Analysis determines why an event happened, not how the evidence was handled.',
      'INCORRECT: An SLA (Service Level Agreement) defines service standards between a provider and a client.'
    ],
    objectiveCodes: ['4.8'],
    tags: ['Forensics', 'Incident Response', 'Legal'],
    threatLevel: 'medium',
    logs: ['FORENSIC_LOG: Hard drive seized at 14:00 by Officer A', 'CHAIN_FORM: Transfer to Analyst B at 14:30 signature verified'],
    refs: [{ source: 'Study Guide', section: '4.8 - Digital Forensics' }]
  },
  {
    id: 'GRC-010',
    domain: 'Governance, Risk, Compliance',
    question: 'A company implements a policy that requires all data on end-of-life hard drives to be irretrievable. Which method provides the highest level of assurance?',
    options: ['Formatting', 'Degaussing', 'Physical Destruction', 'Overwriting'],
    correctIndex: 2,
    explanation: 'Physical Destruction (shredding, incineration) is the most secure method, ensuring data cannot be recovered.',
    rationales: [
      'INCORRECT: Formatting only removes the pointers to the data. The actual data remains and can often be recovered with forensic tools.',
      'INCORRECT: Degaussing (using magnets) works on magnetic drives but is ineffective on SSDs (which use flash memory).',
      'CORRECT: Physical destruction (Shredding/Pulverizing) renders the media physically unusable, guaranteeing no data recovery.',
      'INCORRECT: Overwriting (wiping) is effective but takes time and can sometimes fail on damaged sectors or SSD wear-leveling pools.'
    ],
    objectiveCodes: ['4.2', '2.5'],
    tags: ['Data Privacy', 'Asset Management', 'Sanitization'],
    threatLevel: 'medium',
    logs: ['ASSET_MGMT: 50 Hard drives sent for shredding', 'CERTIFICATE: Destruction certificate received from vendor'],
    refs: [{ source: 'Study Guide', section: '4.2 - Asset Management' }]
  }
];
