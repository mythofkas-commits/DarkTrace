import { Scenario } from '../types';

export const scenarios: Scenario[] = [
  // --- DOMAIN 1: GENERAL SECURITY CONCEPTS (12%) ---
  {
    id: 'GSC-001',
    domain: 'General Security Concepts',
    question: 'A security analyst observes a successful login from the CEO’s account in London at 3:00 AM, followed by another successful login from New York at 3:15 AM. Which concept describes this indicator of compromise?',
    options: ['Impossible Travel', 'Time-of-day Restriction', 'Geofencing', 'Conditional Access'],
    correctIndex: 0,
    explanation: 'Impossible Travel (or concurrent login) detects geographically distant logins occurring within a timeframe physically impossible for a single user to travel. This is a behavioral analytic indicator.',
    threatLevel: 'high',
    logs: ['AUTH_LOG: User "CEO" login Success [London, UK] 03:00:00', 'AUTH_LOG: User "CEO" login Success [New York, USA] 03:15:00', 'SIEM_ALERT: Velocity violation detected']
  },
  {
    id: 'GSC-002',
    domain: 'General Security Concepts',
    question: 'Which cryptographic concept ensures that a sender cannot deny having sent a message?',
    options: ['Confidentiality', 'Non-repudiation', 'Obfuscation', 'Availability'],
    correctIndex: 1,
    explanation: 'Non-repudiation provides proof of the origin of data and the integrity of the data. It prevents a sender from falsely denying that they sent the information, typically achieved via Digital Signatures.',
    threatLevel: 'low',
    logs: ['MAIL_GW: Signature verified', 'PKI_AUDIT: Sender identity confirmed via Private Key']
  },
  {
    id: 'GSC-003',
    domain: 'General Security Concepts',
    question: 'A manufacturing company wants to implement a control that physically prevents vehicles from crashing into the front entrance of their data center. What is the BEST choice?',
    options: ['Motion Sensors', 'Bollards', 'Air Gap', 'Faraday Cage'],
    correctIndex: 1,
    explanation: 'Bollards are heavy vertical posts, often made of concrete or steel, designed to stop vehicles from entering a specific area or crashing into buildings. This is a preventive physical control.',
    threatLevel: 'low',
    logs: ['FACILITY_LOG: Vehicle impact detected at Perimeter Gate 1', 'SECURITY_CAM: Truck stopped by physical barrier']
  },
  {
    id: 'GSC-004',
    domain: 'General Security Concepts',
    question: 'An organization implements a policy where no single person has total control over a critical financial process. Instead, two people must act together to complete the task. This is an example of:',
    options: ['Least Privilege', 'Separation of Duties', 'Two-Person Integrity', 'Background Checks'],
    correctIndex: 2,
    explanation: 'Two-Person Integrity (or Two-Person Control) requires two authorized personnel to be present to perform a task. Separation of Duties ensures one person cannot complete all steps of a critical process alone.',
    threatLevel: 'medium',
    logs: ['FINANCE_SYS: Transaction > $100k initiated by User A', 'FINANCE_SYS: Awaiting approval from User B']
  },
  {
    id: 'GSC-005',
    domain: 'General Security Concepts',
    question: 'Which of the following controls would BEST deceive an attacker into thinking they have successfully breached a network, while simultaneously alerting the security team?',
    options: ['Honeypot', 'WAF', 'DLP', 'Jump Server'],
    correctIndex: 0,
    explanation: 'A Honeypot is a decoy system designed to look like a legitimate target (e.g., a vulnerable server). It has no production value, so any interaction with it is suspicious by definition.',
    threatLevel: 'low',
    logs: ['HONEYPOT_01: SSH Connection from 192.168.1.55', 'IDS_ALERT: Internal scanning detected from compromised host']
  },
  {
    id: 'GSC-006',
    domain: 'General Security Concepts',
    question: 'Which change management component outlines the steps to return a system to its previous state if an update fails?',
    options: ['Backout Plan', 'Impact Analysis', 'Maintenance Window', 'Standard Operating Procedure'],
    correctIndex: 0,
    explanation: 'A Backout Plan (or Rollback Plan) details the specific procedures required to restore a system to its original state if a change implementation fails or causes critical issues.',
    threatLevel: 'low',
    logs: ['CM_DB: Update 10.4 failed integrity check', 'OPS_TEAM: Executing Backout Plan Step 1: Restore Snapshot']
  },

  // --- DOMAIN 2: THREATS, VULNERABILITIES, MITIGATIONS (22%) ---
  {
    id: 'TVM-001',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker uses a "watering hole" strategy to compromise a specific group of users. Which of the following describes this attack?',
    options: ['Sending phishing emails to the entire company', 'Infecting a third-party website frequently visited by the target group', 'Using a brute-force attack on the VPN concentrator', 'Placing malicious USB drives in the parking lot'],
    correctIndex: 1,
    explanation: 'A Watering Hole attack targets a specific group of users by infecting a website they are known to visit. The attacker waits for the victims to visit the "poisoned" site rather than attacking them directly.',
    threatLevel: 'high',
    logs: ['WEB_PROXY: User visited "industry-news-site.com"', 'EDR_ALERT: Malicious script executed from browser cache']
  },
  {
    id: 'TVM-002',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A user reports their computer performance has degraded significantly. The security team discovers a process utilizing 95% of the GPU. What type of malware is likely installed?',
    options: ['Ransomware', 'Cryptominer', 'Logic Bomb', 'Rootkit'],
    correctIndex: 1,
    explanation: 'Cryptominers (Cryptojacking) steal computing resources (CPU/GPU) to mine cryptocurrency. High resource utilization and sluggish performance are key indicators.',
    threatLevel: 'medium',
    logs: ['PERF_MON: GPU usage sustained at 98%', 'NET_FLOW: Outbound connection to known mining pool port 3333']
  },
  {
    id: 'TVM-003',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker inputs "\' OR 1=1; --" into a website login field and gains administrative access. What type of attack is this?',
    options: ['XSS', 'SQL Injection', 'CSRF', 'Buffer Overflow'],
    correctIndex: 1,
    explanation: 'SQL Injection (SQLi) involves injecting malicious SQL commands into input fields. The payload "\' OR 1=1" evaluates to TRUE, often bypassing authentication logic.',
    threatLevel: 'critical',
    logs: ['DB_QUERY: SELECT * FROM users WHERE user = \'admin\' OR 1=1', 'WAF_BLOCK: SQL keyword detected in POST body']
  },
  {
    id: 'TVM-004',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A malicious actor calls the help desk pretending to be the CEO, claiming they forgot their password and demanding an immediate reset. This is an example of:',
    options: ['Vishing', 'Tailgating', 'Dumpster Diving', 'Whaling'],
    correctIndex: 0,
    explanation: 'Vishing (Voice Phishing) uses the telephone to deceive victims. While impersonating the CEO is a form of social engineering, doing it over the phone specifically classifies it as Vishing.',
    threatLevel: 'medium',
    logs: ['VOIP_SYS: Incoming call from external number', 'HELPDESK_TICKET: Password reset requested by "CEO" (Verification skipped)']
  },
  {
    id: 'TVM-005',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which vulnerability occurs when an application does not properly validate the size of input data, allowing data to be written beyond the allocated memory space?',
    options: ['Buffer Overflow', 'Race Condition', 'Memory Leak', 'Pointer Dereference'],
    correctIndex: 0,
    explanation: 'A Buffer Overflow occurs when an application writes more data to a block of memory (buffer) than it is allocated to hold, potentially overwriting adjacent memory and causing a crash or code execution.',
    threatLevel: 'critical',
    logs: ['APP_CRASH: Segmentation fault at memory address 0x000F', 'IDS_SIG: Shellcode pattern detected in UDP payload']
  },
  {
    id: 'TVM-006',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A user receives a text message claiming to be from their bank with a link to verify a transaction. The link leads to a fake site. What is this attack called?',
    options: ['Phishing', 'Smishing', 'Spim', 'Pharming'],
    correctIndex: 1,
    explanation: 'Smishing (SMS Phishing) is phishing conducted via SMS (text messages). It exploits the trust users place in mobile messaging.',
    threatLevel: 'medium',
    logs: ['MOBILE_GATEWAY: Malicious URL detected in SMS', 'USER_REPORT: Suspicious text asking for credentials']
  },
  {
    id: 'TVM-007',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which type of malware disguises itself as legitimate software to trick the user into installing it?',
    options: ['Worm', 'Trojan', 'Virus', 'Logic Bomb'],
    correctIndex: 1,
    explanation: 'A Trojan Horse (Trojan) pretends to be beneficial software (like a game or utility) but contains a malicious payload. Unlike worms, Trojans require user interaction to install.',
    threatLevel: 'high',
    logs: ['ENDPOINT_AV: "FreeScreensaver.exe" detected as Trojan.Win32.Generic', 'SYS_EVENT: Unexpected outbound connection from new process']
  },
  {
    id: 'TVM-008',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker intercepts communication between a user and a Wi-Fi access point, relaying messages between them. What type of attack is this?',
    options: ['On-path (Man-in-the-Middle)', 'DDoS', 'Bluejacking', 'Replay'],
    correctIndex: 0,
    explanation: 'An On-path attack (formerly Man-in-the-Middle) involves an attacker inserting themselves between two communicating parties to intercept or modify traffic.',
    threatLevel: 'high',
    logs: ['WIFI_IDS: Duplicate MAC address detected', 'SSL_ERROR: Certificate mismatch for google.com']
  },
  {
    id: 'TVM-009',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which attack involves an attacker sending thousands of SYN packets to a server with a spoofed IP address, attempting to exhaust the server’s resources?',
    options: ['SYN Flood', 'Ping of Death', 'DNS Amplification', 'ARP Poisoning'],
    correctIndex: 0,
    explanation: 'A SYN Flood is a DoS attack where the attacker sends a succession of SYN requests to a target\'s system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic.',
    threatLevel: 'critical',
    logs: ['FW_ALERT: High rate of half-open TCP connections', 'SERVER_LOG: Unable to allocate memory for new socket']
  },
  {
    id: 'TVM-010',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A security researcher discovers a vulnerability in a web browser that has no vendor patch available. This is known as a:',
    options: ['Zero-day', 'Legacy exploit', 'Default configuration', 'Misconfiguration'],
    correctIndex: 0,
    explanation: 'A Zero-day vulnerability is a flaw that is unknown to the vendor, meaning they have had "zero days" to fix it. These are highly dangerous as no official patch exists.',
    threatLevel: 'critical',
    logs: ['THREAT_INTEL: New exploit detected in wild targeting Chrome', 'VULN_SCAN: No CVE match found - Potential 0-day']
  },

  // --- DOMAIN 3: SECURITY ARCHITECTURE (18%) ---
  {
    id: 'ARC-001',
    domain: 'Security Architecture',
    question: 'Which cloud model provides the customer with the highest level of control over the operating systems and applications?',
    options: ['SaaS', 'PaaS', 'IaaS', 'FaaS'],
    correctIndex: 2,
    explanation: 'Infrastructure as a Service (IaaS) provides virtualized computing resources over the internet. The customer manages the OS, applications, and data, while the provider manages the hardware.',
    threatLevel: 'low',
    logs: ['CLOUD_CONSOLE: VM instance "Web-01" provisioned', 'SYS_ADMIN: Installing Linux kernel patches on IaaS instance']
  },
  {
    id: 'ARC-002',
    domain: 'Security Architecture',
    question: 'An administrator wants to securely manage a fleet of mobile devices, including enforcing encryption and remote wipe capabilities. Which solution should be implemented?',
    options: ['MDM', 'MFA', 'VPN', 'DLP'],
    correctIndex: 0,
    explanation: 'Mobile Device Management (MDM) allows administrators to secure, monitor, and manage mobile devices. Key features include enforcing passcodes, encryption, and remote wipe.',
    threatLevel: 'low',
    logs: ['MDM_SERVER: Policy "Enforce_Encryption" applied to 50 devices', 'MDM_ACTION: Remote wipe command sent to lost device ID 9942']
  },
  {
    id: 'ARC-003',
    domain: 'Security Architecture',
    question: 'Which concept involves separating a network into smaller, isolated sections to improve security and performance?',
    options: ['Segmentation', 'Aggregation', 'Virtualization', 'Encryption'],
    correctIndex: 0,
    explanation: 'Network Segmentation divides a network into smaller subnets (e.g., VLANs). This limits lateral movement for attackers and improves performance by reducing broadcast traffic.',
    threatLevel: 'medium',
    logs: ['SWITCH_CONFIG: VLAN 10 (HR) and VLAN 20 (Engineering) created', 'FW_RULE: Block traffic from VLAN 20 to VLAN 10']
  },
  {
    id: 'ARC-004',
    domain: 'Security Architecture',
    question: 'A developer wants to ensure that no one can access the API keys stored in their application code. What is the BEST architectural practice?',
    options: ['Hardcoding keys in comments', 'Storing keys in a public repo', 'Using a Secrets Manager / Vault', 'Rotating keys annually'],
    correctIndex: 2,
    explanation: 'A Secrets Manager (or Vault) is a dedicated tool for securely storing and managing sensitive information like API keys, passwords, and certificates, preventing them from being hardcoded.',
    threatLevel: 'medium',
    logs: ['APP_LOG: Retrieving DB_PASSWORD from HashiCorp Vault', 'GIT_SCAN: No secrets detected in source code']
  },
  {
    id: 'ARC-005',
    domain: 'Security Architecture',
    question: 'Which architecture model assumes that no user or device should be trusted by default, even if they are inside the corporate network?',
    options: ['Defense in Depth', 'Zero Trust', 'Perimeter Security', 'Air Gapped'],
    correctIndex: 1,
    explanation: 'Zero Trust architecture operates on the principle of "never trust, always verify." It requires continuous verification of identity and device posture for every access request, regardless of location.',
    threatLevel: 'medium',
    logs: ['ZTA_GATEWAY: User authenticated but device health check failed', 'ACCESS_DENIED: Resource "HR_Data" blocked due to low trust score']
  },
  {
    id: 'ARC-006',
    domain: 'Security Architecture',
    question: 'A company needs to ensure that critical industrial control systems (ICS) are completely isolated from the internet and the corporate network. Which strategy should be used?',
    options: ['Air Gap', 'DMZ', 'VPN', 'VLAN'],
    correctIndex: 0,
    explanation: 'An Air Gap is a physical security measure that ensures a secure network is physically isolated from unsecured networks, such as the public internet or an unsecured local area network.',
    threatLevel: 'high',
    logs: ['NETWORK_AUDIT: No physical path found between ICS and Corp LAN', 'PHYSICAL_INSPECT: Visual confirmation of air gap']
  },
  {
    id: 'ARC-007',
    domain: 'Security Architecture',
    question: 'Which type of load balancer uses client IP addresses to ensure that a user is always directed to the same backend server for the duration of their session?',
    options: ['Round Robin', 'Persistence / Affinity', 'Least Connections', 'Weighted Response'],
    correctIndex: 1,
    explanation: 'Session Persistence (or Affinity) ensures that a user\'s session remains on the specific server that serviced their initial request. This is crucial for applications that maintain session state locally.',
    threatLevel: 'low',
    logs: ['LB_LOG: Client 192.168.1.10 pinned to Server-A', 'APP_DEBUG: Session state retrieved from local memory']
  },
  {
    id: 'ARC-008',
    domain: 'Security Architecture',
    question: 'To securely manage a remote server, an administrator should use which protocol instead of Telnet?',
    options: ['HTTP', 'SSH', 'FTP', 'SNMP'],
    correctIndex: 1,
    explanation: 'SSH (Secure Shell) provides a secure channel over an unsecured network. It encrypts the session, unlike Telnet which sends data (including passwords) in plain text.',
    threatLevel: 'medium',
    logs: ['FW_ALLOW: TCP Port 22 (SSH) from Admin_IP', 'SSH_DAEMON: Successful public key authentication for root']
  },
  {
    id: 'ARC-009',
    domain: 'Security Architecture',
    question: 'A company is deploying a web application that must be accessible from the internet but needs to be protected from direct internet attacks. Where should the web servers be placed?',
    options: ['Intranet', 'DMZ (Screened Subnet)', 'Air Gapped Network', 'Management VLAN'],
    correctIndex: 1,
    explanation: 'A DMZ (Demilitarized Zone) or Screened Subnet is a physical or logical subnetwork that contains and exposes an organization\'s external-facing services to an untrusted network (Internet).',
    threatLevel: 'medium',
    logs: ['FW_CONFIG: Internet -> DMZ (Port 443) ALLOW', 'FW_CONFIG: DMZ -> Internal LAN (All Ports) DENY']
  },

  // --- DOMAIN 4: SECURITY OPERATIONS (28%) ---
  {
    id: 'OPS-001',
    domain: 'Security Operations',
    question: 'A SOC analyst receives an alert from the SIEM about multiple failed login attempts followed by a successful login. What is the FIRST step in the incident response process?',
    options: ['Preparation', 'Identification', 'Containment', 'Eradication'],
    correctIndex: 1,
    explanation: 'Identification (or Detection) is the process of determining whether an event is actually a security incident. Validating the SIEM alert is part of this phase.',
    threatLevel: 'high',
    logs: ['SIEM_CORRELATION: Brute force pattern detected', 'ANALYST_NOTE: Validating log source and timestamps']
  },
  {
    id: 'OPS-002',
    domain: 'Security Operations',
    question: 'Which tool would a security analyst use to capture and analyze network traffic in real-time to troubleshoot a connectivity issue or investigate a breach?',
    options: ['Nmap', 'Wireshark', 'Netcat', 'Hashcat'],
    correctIndex: 1,
    explanation: 'Wireshark is a packet analyzer used for network troubleshooting, analysis, software and communications protocol development, and education. It captures raw packets.',
    threatLevel: 'low',
    logs: ['PACKET_CAP: PCAP file saved', 'ANALYSIS: Discovered cleartext password in FTP stream']
  },
  {
    id: 'OPS-003',
    domain: 'Security Operations',
    question: 'During a forensic investigation, which of the following must be documented to prove that evidence has been handled securely and has not been tampered with?',
    options: ['Chain of Custody', 'Incident Report', 'Root Cause Analysis', 'SLA'],
    correctIndex: 0,
    explanation: 'The Chain of Custody is a chronological documentation or paper trail that records the sequence of custody, control, transfer, analysis, and disposition of physical or electronic evidence.',
    threatLevel: 'medium',
    logs: ['FORENSIC_LOG: Hard drive seized at 14:00 by Officer A', 'CHAIN_FORM: Transfer to Analyst B at 14:30 signature verified']
  },
  {
    id: 'OPS-004',
    domain: 'Security Operations',
    question: 'Which scanning type authenticates with the target system to provide a more comprehensive view of vulnerabilities?',
    options: ['Non-credentialed Scan', 'Credentialed Scan', 'Passive Scan', 'Discovery Scan'],
    correctIndex: 1,
    explanation: 'A Credentialed Scan uses valid user credentials to log in to the target system. This allows the scanner to inspect the internal configuration, registry, and file system, finding vulnerabilities a non-credentialed scan would miss.',
    threatLevel: 'low',
    logs: ['VULN_SCAN: Authentication successful', 'SCAN_RESULT: Found missing patches in Windows Registry']
  },
  {
    id: 'OPS-005',
    domain: 'Security Operations',
    question: 'An organization uses a centralized system to collect logs from firewalls, servers, and routers to correlate events and detect threats. What is this system called?',
    options: ['IPS', 'SIEM', 'DLP', 'WAF'],
    correctIndex: 1,
    explanation: 'A Security Information and Event Management (SIEM) system aggregates log data from various sources, correlates it to identify patterns, and generates alerts for potential security incidents.',
    threatLevel: 'low',
    logs: ['SIEM_INGEST: Receiving logs from 150 sources', 'SIEM_RULE: Correlation rule "Malware Outbreak" triggered']
  },
  {
    id: 'OPS-006',
    domain: 'Security Operations',
    question: 'A security team is conducting a tabletop exercise to simulate a ransomware attack. What is the primary purpose of this exercise?',
    options: ['To test backup speeds', 'To validate the incident response plan', 'To patch vulnerabilities', 'To configure the firewall'],
    correctIndex: 1,
    explanation: 'Tabletop exercises are discussion-based sessions where team members meet to discuss their roles and responses to a particular emergency situation. The goal is to validate and improve the Incident Response Plan.',
    threatLevel: 'low',
    logs: ['TTX_SESSION: Scenario "CryptoLocker" initiated', 'AAR_REPORT: Communication delay identified between IT and Legal']
  },
  {
    id: 'OPS-007',
    domain: 'Security Operations',
    question: 'Which data sensitivity label would be MOST appropriate for a database containing customer credit card numbers and social security numbers?',
    options: ['Public', 'Internal', 'Confidential', 'Unclassified'],
    correctIndex: 2,
    explanation: 'Confidential (or Restricted/Private) is appropriate for highly sensitive data that, if compromised, could cause significant damage to the organization or individuals (e.g., PII, PCI data).',
    threatLevel: 'medium',
    logs: ['DLP_SCAN: Labeling file "customers.db" as CONFIDENTIAL', 'ACCESS_CONTROL: Restricting read access to "Finance_Admins" group']
  },
  {
    id: 'OPS-008',
    domain: 'Security Operations',
    question: 'After a security incident has been contained and eradicated, the team meets to discuss what went wrong and how to improve. What is this phase called?',
    options: ['Preparation', 'Identification', 'Lessons Learned', 'Recovery'],
    correctIndex: 2,
    explanation: 'The Lessons Learned (or Post-Incident Activity) phase involves analyzing the incident to identify weaknesses in the response process and implementing changes to prevent recurrence.',
    threatLevel: 'low',
    logs: ['MEETING_MINUTES: Reviewing incident timeline', 'ACTION_ITEM: Update firewall rules based on attack vector']
  },
  {
    id: 'OPS-009',
    domain: 'Security Operations',
    question: 'What is the order of volatility when collecting digital evidence?',
    options: ['Disk, RAM, CPU Cache', 'CPU Cache, RAM, Disk', 'RAM, Disk, CPU Cache', 'Disk, CPU Cache, RAM'],
    correctIndex: 1,
    explanation: 'Order of volatility dictates collecting the most volatile data first. CPU Cache/Registers are most volatile, followed by RAM (Routing tables, ARP cache), then Swap/Page file, and finally Hard Disk.',
    threatLevel: 'medium',
    logs: ['FORENSIC_PROC: Dumping RAM contents before power down', 'EVIDENCE_LOG: Volatile data secured']
  },
  {
    id: 'OPS-010',
    domain: 'Security Operations',
    question: 'A firewall administrator configures a rule to block all traffic on port 23. Which protocol is being blocked?',
    options: ['SSH', 'FTP', 'Telnet', 'SMTP'],
    correctIndex: 2,
    explanation: 'Telnet uses TCP port 23. It is an insecure, cleartext protocol and is commonly blocked in favor of SSH (port 22).',
    threatLevel: 'medium',
    logs: ['FW_DENY: Src: 192.168.1.50 Dst: 10.1.10.5 Proto: TCP Port: 23', 'POLICY_CHECK: Telnet traffic prohibited']
  },

  // --- DOMAIN 5: GOVERNANCE, RISK, AND COMPLIANCE (20%) ---
  {
    id: 'GRC-001',
    domain: 'Governance, Risk, Compliance',
    question: 'A company processes credit card payments. Which compliance standard must they adhere to?',
    options: ['HIPAA', 'GDPR', 'PCI DSS', 'SOX'],
    correctIndex: 2,
    explanation: 'The Payment Card Industry Data Security Standard (PCI DSS) is a set of security standards designed to ensure that ALL companies that accept, process, store, or transmit credit card information maintain a secure environment.',
    threatLevel: 'medium',
    logs: ['COMPLIANCE_AUDIT: Checking for encrypted transmission of cardholder data', 'FAIL: PAN found in cleartext log']
  },
  {
    id: 'GRC-002',
    domain: 'Governance, Risk, Compliance',
    question: 'Which regulation specifically protects the privacy of personal data for European Union citizens?',
    options: ['NIST', 'GDPR', 'ISO 27001', 'FERPA'],
    correctIndex: 1,
    explanation: 'The General Data Protection Regulation (GDPR) is a regulation in EU law on data protection and privacy in the European Union and the European Economic Area.',
    threatLevel: 'high',
    logs: ['PRIVACY_REQ: "Right to be forgotten" request received', 'DB_ADMIN: Purging user records for EU citizen ID 4492']
  },
  {
    id: 'GRC-003',
    domain: 'Governance, Risk, Compliance',
    question: 'A security manager calculates that a specific server fails once every 2 years, and the cost to repair it is $1,000. What is the Annualized Loss Expectancy (ALE)?',
    options: ['$500', '$1,000', '$2,000', '$250'],
    correctIndex: 0,
    explanation: 'ALE = Single Loss Expectancy (SLE) x Annualized Rate of Occurrence (ARO). SLE is $1,000. ARO is 0.5 (once every 2 years). ALE = $1,000 * 0.5 = $500.',
    threatLevel: 'low',
    logs: ['RISK_CALC: SLE=$1000, ARO=0.5', 'REPORT: Annual reserve set to $500']
  },
  {
    id: 'GRC-004',
    domain: 'Governance, Risk, Compliance',
    question: 'A company decides to purchase cybersecurity insurance to cover the potential financial loss of a data breach. Which risk response strategy is this?',
    options: ['Risk Avoidance', 'Risk Acceptance', 'Risk Mitigation', 'Risk Transfer'],
    correctIndex: 2,
    explanation: 'Risk Transfer (or Sharing) involves shifting the burden of the risk to another party, such as an insurance company. You are paying a premium to have someone else handle the financial impact.',
    threatLevel: 'low',
    logs: ['POLICY_REVIEW: Insurance premium paid', 'RISK_REGISTER: Breach financial impact transferred to insurer']
  },
  {
    id: 'GRC-005',
    domain: 'Governance, Risk, Compliance',
    question: 'Which document outlines the rules of behavior for employees when using company IT resources?',
    options: ['SLA', 'AUP', 'NDA', 'MOU'],
    correctIndex: 1,
    explanation: 'An Acceptable Use Policy (AUP) is a document stipulating constraints and practices that a user must agree to for access to a corporate network or the internet.',
    threatLevel: 'low',
    logs: ['HR_ONBOARDING: New employee signed AUP', 'POLICY_VIOLATION: User visited gambling site (violation of AUP)']
  },
  {
    id: 'GRC-006',
    domain: 'Governance, Risk, Compliance',
    question: 'A third-party vendor requires access to the company network. Which document should be signed to ensure they do not disclose confidential information?',
    options: ['SLA', 'ISA', 'NDA', 'BPA'],
    correctIndex: 2,
    explanation: 'A Non-Disclosure Agreement (NDA) is a legal contract between at least two parties that outlines confidential material, knowledge, or information that the parties wish to share with one another for certain purposes, but wish to restrict access to.',
    threatLevel: 'medium',
    logs: ['LEGAL_DEPT: Vendor NDA signed and filed', 'ACCESS_GRANT: Vendor account created']
  },
  {
    id: 'GRC-007',
    domain: 'Governance, Risk, Compliance',
    question: 'The Maximum Tolerable Downtime (MTD) is usually the sum of which two metrics?',
    options: ['RPO and RTO', 'MTBF and MTTR', 'RTO and WRT', 'SLE and ARO'],
    correctIndex: 0,
    explanation: 'While definitions vary slightly, MTD is the total time a process can be down without causing irreparable harm. It effectively sets the ceiling for the Recovery Time Objective (RTO). Note: RTO + Work Recovery Time (WRT) is a more precise definition, but in CompTIA context, it relates closely to RTO limits.',
    threatLevel: 'medium',
    logs: ['BCP_MEETING: Critical function MTD defined as 4 hours', 'DR_TEST: Recovery exceeded RTO limits']
  },
  {
    id: 'GRC-008',
    domain: 'Governance, Risk, Compliance',
    question: 'Which type of security control is a "Warning: Authorized Personnel Only" sign?',
    options: ['Preventive', 'Deterrent', 'Detective', 'Corrective'],
    correctIndex: 1,
    explanation: 'A Deterrent control is designed to discourage a potential attacker. A sign warns them of consequences but does not physically stop them (like a fence would, which is preventive).',
    threatLevel: 'low',
    logs: ['PHYSICAL_AUDIT: Warning signs posted at all entrances', 'OBSERVATION: Intruder turned away after reading sign']
  },
  {
    id: 'GRC-009',
    domain: 'Governance, Risk, Compliance',
    question: 'Which role is responsible for processing data on behalf of the data controller?',
    options: ['Data Owner', 'Data Custodian', 'Data Processor', 'Data Protection Officer'],
    correctIndex: 2,
    explanation: 'In GDPR terms, a Data Processor is an entity that processes personal data on behalf of the controller. The controller determines the purpose and means of processing.',
    threatLevel: 'low',
    logs: ['CONTRACT_REVIEW: Cloud provider defined as Data Processor', 'COMPLIANCE: Processor agreement updated']
  },
  {
    id: 'GRC-010',
    domain: 'Governance, Risk, Compliance',
    question: 'A company implements a policy that requires all data on end-of-life hard drives to be irretrievable. Which method provides the highest level of assurance?',
    options: ['Formatting', 'Degaussing', 'Physical Destruction', 'Overwriting'],
    correctIndex: 2,
    explanation: 'Physical Destruction (shredding, incineration, pulverizing) is the most secure method of media sanitization, ensuring that data cannot be recovered by any means.',
    threatLevel: 'medium',
    logs: ['ASSET_MGMT: 50 Hard drives sent for shredding', 'CERTIFICATE: Destruction certificate received from vendor']
  }
];