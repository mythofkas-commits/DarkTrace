
import { Scenario } from '../types';

export const scenarios: Scenario[] = [
  // --- PRACTICE EXAM A EXTRACTS ---
  
  {
    id: 'EXAM-A-Q06',
    domain: 'Governance, Risk, Compliance',
    question: 'A company has hired a third-party to gather information about the company’s servers and data. This third-party will not have direct access to the company\'s internal network, but they can gather information from any other source. Which of the following would BEST describe this approach?',
    options: ['Vulnerability scanning', 'Passive reconnaissance', 'Supply chain analysis', 'Regulatory audit'],
    correctIndex: 1,
    explanation: 'Passive reconnaissance focuses on gathering as much information from open sources such as social media, corporate websites, and business organizations without interacting directly with the target systems.',
    rationales: [
      'INCORRECT: Vulnerability scanning is an active process that queries systems directly to find weaknesses.',
      'CORRECT: Passive reconnaissance gathers data from open sources (OSINT) without touching the target\'s infrastructure.',
      'INCORRECT: Supply chain analysis examines the security of vendors and suppliers, not the company\'s own public footprint.',
      'INCORRECT: A regulatory audit is a formal verification of compliance with laws or standards, usually requiring internal access.'
    ],
    objectiveCodes: ['5.5'],
    tags: ['Reconnaissance', 'OSINT', 'Penetration Testing'],
    threatLevel: 'low',
    logs: ['OSINT_TOOL: Scraped 500 email addresses from LinkedIn', 'DNS_LOOKUP: Resolved external mail servers'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 43 }]
  },
  {
    id: 'EXAM-A-Q07',
    domain: 'Security Operations',
    question: 'A company\'s email server has received an email from a third-party, but the origination server does not match the list of authorized devices. Which of the following would determine the disposition of this message?',
    options: ['SPF', 'NAC', 'DMARC', 'DKIM'],
    correctIndex: 2,
    explanation: 'DMARC (Domain-based Message Authentication Reporting and Conformance) uses SPF and DKIM records to determine if a message should be accepted, rejected, or flagged as spam.',
    rationales: [
      'INCORRECT: SPF (Sender Policy Framework) simply lists authorized IP addresses but does not determine the final disposition of the message.',
      'INCORRECT: NAC (Network Access Control) manages device access to a network, not email message validation.',
      'CORRECT: DMARC is the policy layer that tells the receiving server what to do (Reject/Quarantine) if SPF/DKIM fail.',
      'INCORRECT: DKIM (Domain Keys Identified Mail) validates the integrity of the message via digital signature but does not set the rejection policy.'
    ],
    objectiveCodes: ['4.5'],
    tags: ['Email Security', 'Protocols', 'DMARC'],
    threatLevel: 'medium',
    logs: ['SMTP_IN: Message from 192.0.2.1 failed DMARC check', 'ACTION: REJECT per policy'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 44 }]
  },
  {
    id: 'EXAM-A-Q08',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which of these threat actors would be MOST likely to attack systems for direct financial gain?',
    options: ['Organized crime', 'Hacktivist', 'Nation state', 'Shadow IT'],
    correctIndex: 0,
    explanation: 'Organized crime groups are primarily motivated by financial profit, often using ransomware, fraud, or theft of sellable data.',
    rationales: [
      'CORRECT: Organized crime is sophisticated and funded, specifically targeting financial ROI (Return on Investment).',
      'INCORRECT: Hacktivists are motivated by political, social, or ideological causes, not primarily money.',
      'INCORRECT: Nation states are motivated by espionage, strategic advantage, or geopolitical warfare.',
      'INCORRECT: Shadow IT refers to internal employees using unauthorized software, not external attackers seeking profit.'
    ],
    objectiveCodes: ['2.1'],
    tags: ['Threat Actors', 'Cybercrime'],
    threatLevel: 'high',
    logs: ['INTEL: Actor group "FIN7" identified', 'ALERT: Ransomware payment channel detected'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 45 }]
  },
  {
    id: 'EXAM-A-Q12',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A security administrator is concerned about the potential for data exfiltration using external storage drives. Which of the following would be the BEST way to prevent this method of data exfiltration?',
    options: ['Block removable media via OS policy', 'Monitor host-based firewall logs', 'Allow only approved apps', 'Define block rule in UTM'],
    correctIndex: 0,
    explanation: 'Disabling removable media (USB drives) via Group Policy or OS security settings allows the organization to physically prevent data from being copied to external devices.',
    rationales: [
      'CORRECT: Creating an OS policy to disable USB storage is a preventive control against physical exfiltration.',
      'INCORRECT: Host-based firewalls monitor network traffic, not physical port usage like USB.',
      'INCORRECT: Application allow-listing prevents unauthorized software but does not stop a user from copying files to a USB drive.',
      'INCORRECT: A UTM (Unified Threat Management) appliance filters network traffic, not physical ports on endpoints.'
    ],
    objectiveCodes: ['2.2'],
    tags: ['Data Loss Prevention', 'Endpoint Security', 'USB'],
    threatLevel: 'medium',
    logs: ['POWERSHELL: Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR -Name "Start" -Value 4', 'USB_EVENT: Blocked Mass Storage Device'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 49 }]
  },
  {
    id: 'EXAM-A-Q18',
    domain: 'Governance, Risk, Compliance',
    question: 'A system administrator is working on a contract that will specify a minimum required uptime for a set of Internet-facing firewalls. The administrator needs to know how often the firewall hardware is expected to fail between repairs. Which of the following would BEST describe this information?',
    options: ['MTBF', 'RTO', 'MTTR', 'RPO'],
    correctIndex: 0,
    explanation: 'MTBF (Mean Time Between Failures) predicts the reliability of a product by estimating the average time between hardware failures.',
    rationales: [
      'CORRECT: MTBF measures reliability and expected lifespan before a failure occurs.',
      'INCORRECT: RTO (Recovery Time Objective) is the target time to restore a service *after* a disaster.',
      'INCORRECT: MTTR (Mean Time To Repair) is the average time required to fix a failed component.',
      'INCORRECT: RPO (Recovery Point Objective) defines the maximum acceptable data loss (measured in time) during a recovery.'
    ],
    objectiveCodes: ['5.2'],
    tags: ['Risk Management', 'Metrics', 'Availability'],
    threatLevel: 'low',
    logs: ['ASSET_DB: Firewall-01 MTBF = 50,000 Hours', 'SLA_CALC: Uptime requirements updated'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 56 }]
  },
  {
    id: 'EXAM-A-Q24',
    domain: 'General Security Concepts',
    question: 'What kind of security control is associated with a login banner?',
    options: ['Preventive', 'Deterrent', 'Corrective', 'Detective'],
    correctIndex: 1,
    explanation: 'A login banner acts as a deterrent by warning potential attackers of the legal consequences of unauthorized access. It does not physically stop them.',
    rationales: [
      'INCORRECT: Preventive controls (like a firewall or locked door) physically stop an action.',
      'CORRECT: Deterrent controls discourage an action by warning of consequences.',
      'INCORRECT: Corrective controls (like restoring a backup) fix damage after an incident.',
      'INCORRECT: Detective controls (like a security camera or log file) record the event for later analysis.'
    ],
    objectiveCodes: ['1.1'],
    tags: ['Security Controls', 'Legal'],
    threatLevel: 'low',
    logs: ['POLICY_UPDATE: Login banner text set to "UNAUTHORIZED ACCESS PROHIBITED"', 'SSH_CONFIG: Banner /etc/issue.net enabled'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 62 }]
  },
  {
    id: 'EXAM-A-Q30',
    domain: 'Security Operations',
    question: 'A company is creating a security policy for corporate mobile devices: 1) Auto-lock after time period. 2) Location traceable. 3) User info separate from company data. Which solution BEST establishes these rules?',
    options: ['Segmentation', 'Biometrics', 'COPE', 'MDM'],
    correctIndex: 3,
    explanation: 'MDM (Mobile Device Management) is a centralized solution to enforce policies (like lock timers), track devices (GPS), and containerize data (segmentation) on mobile devices.',
    rationales: [
      'INCORRECT: Segmentation is a feature (containerization) but does not provide the platform for management or tracking.',
      'INCORRECT: Biometrics provides authentication but cannot enforce lock timers or track location.',
      'INCORRECT: COPE (Corporate Owned, Personally Enabled) is a deployment model, not the technical solution for enforcement.',
      'CORRECT: MDM is the technology platform used to deploy and enforce these specific security policies.'
    ],
    objectiveCodes: ['4.1'],
    tags: ['Mobile Security', 'MDM', 'BYOD'],
    threatLevel: 'medium',
    logs: ['MDM_PUSH: Policy "Corp_Security_v2" applied to 450 devices', 'MDM_ALERT: Device ID 9942 non-compliant (Encryption disabled)'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 68 }]
  },
  {
    id: 'EXAM-A-Q44',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker has discovered a way to disable a server by sending specially crafted packets from many remote devices to the operating system. When the packet is received, the system crashes and must be rebooted. Which attack is this?',
    options: ['Privilege escalation', 'SQL injection', 'Replay attack', 'DDoS'],
    correctIndex: 3,
    explanation: 'DDoS (Distributed Denial of Service) uses multiple remote devices to overwhelm or crash a target system, denying availability.',
    rationales: [
      'INCORRECT: Privilege escalation involves gaining higher level access rights, not crashing the system.',
      'INCORRECT: SQL injection attacks the database layer to steal or modify data, not crash the OS via packets.',
      'INCORRECT: A replay attack captures and retransmits valid data to gain unauthorized access, not to crash the server.',
      'CORRECT: The attack uses "many remote devices" to "disable a server," which is the definition of a DDoS.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['DoS', 'Network Attacks', 'Availability'],
    threatLevel: 'critical',
    logs: ['NET_FLOW: Inbound traffic spike > 10Gbps', 'KERNEL_PANIC: Malformed TCP packet received'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 82 }]
  },
  {
    id: 'EXAM-A-Q56',
    domain: 'General Security Concepts',
    question: 'An organization is installing a UPS for their new data center. Which of the following would BEST describe this control type?',
    options: ['Compensating', 'Directive', 'Deterrent', 'Detective'],
    correctIndex: 0,
    explanation: 'A Compensating control provides an alternative solution to a security weakness. A UPS compensates for the weakness of unreliable power grids.',
    rationales: [
      'CORRECT: A UPS compensates for the loss of primary power, ensuring availability.',
      'INCORRECT: Directive controls are administrative policies (e.g., "Do not prop open the door").',
      'INCORRECT: Deterrent controls discourage attacks (e.g., a "Beware of Dog" sign).',
      'INCORRECT: Detective controls identify events (e.g., a smoke detector).'
    ],
    objectiveCodes: ['1.1'],
    tags: ['Resiliency', 'Physical Security', 'Availability'],
    threatLevel: 'low',
    logs: ['FACILITY_MON: Main power lost', 'UPS_STATUS: On Battery - Runtime 45 mins'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 94 }]
  },
  {
    id: 'EXAM-A-Q57',
    domain: 'General Security Concepts',
    question: 'A manufacturing company would like to track the progress of parts used on an assembly line. Which of the following technologies would be the BEST choice for this task?',
    options: ['Secure enclave', 'Blockchain', 'Hashing', 'Asymmetric encryption'],
    correctIndex: 1,
    explanation: 'Blockchain provides a distributed, immutable ledger perfect for tracking supply chain steps and verifying component history.',
    rationales: [
      'INCORRECT: Secure enclave is a hardware feature for storing secrets on a chip.',
      'CORRECT: Blockchain creates a permanent, non-modifiable record of every step in the assembly process.',
      'INCORRECT: Hashing verifies integrity of a single file but does not track progress over time.',
      'INCORRECT: Asymmetric encryption provides confidentiality and signing, but is not a tracking mechanism by itself.'
    ],
    objectiveCodes: ['1.4'],
    tags: ['Emerging Tech', 'Integrity', 'Supply Chain'],
    threatLevel: 'low',
    logs: ['LEDGER_UPDATE: Part #55443 verified at Station 4', 'BLOCK_HASH: 0x99a... added to chain'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 95 }]
  },
  {
    id: 'EXAM-A-Q65',
    domain: 'Security Architecture',
    question: 'A company is installing a new application in a public cloud. Which of the following determines the assignment of data security in this cloud infrastructure?',
    options: ['Playbook', 'Audit committee', 'Responsibility matrix', 'Right-to-audit clause'],
    correctIndex: 2,
    explanation: 'A cloud responsibility matrix (Shared Responsibility Model) defines which security tasks belong to the provider (cloud) and which belong to the customer.',
    rationales: [
      'INCORRECT: A playbook is a set of instructions for incident response.',
      'INCORRECT: An audit committee oversees compliance but does not define the cloud provider\'s technical obligations.',
      'CORRECT: The matrix specifies who patches the OS, who encrypts the data, etc.',
      'INCORRECT: A right-to-audit clause allows the customer to inspect the provider, but does not define the security roles.'
    ],
    objectiveCodes: ['3.1'],
    tags: ['Cloud Security', 'Governance', 'Shared Responsibility'],
    threatLevel: 'medium',
    logs: ['COMPLIANCE_CHECK: Reviewing AWS Shared Responsibility Model', 'CONFIG: Customer responsible for "Data at Rest" encryption'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 103 }]
  },
  {
    id: 'EXAM-A-Q74',
    domain: 'General Security Concepts',
    question: 'A security manager would like to ensure that unique hashes are used with an application login process. Which of the following would be the BEST way to add random data when generating a set of stored password hashes?',
    options: ['Salting', 'Obfuscation', 'Key stretching', 'Digital signature'],
    correctIndex: 0,
    explanation: 'Salting adds random data to a password before hashing it. This ensures that even if two users have the same password, their stored hashes are different.',
    rationales: [
      'CORRECT: Salting defends against Rainbow Table attacks by ensuring hash uniqueness.',
      'INCORRECT: Obfuscation hides code logic, it does not randomize password hashes.',
      'INCORRECT: Key stretching (like PBKDF2) slows down the hashing process to resist brute force, but "uniqueness" is primarily achieved via salt.',
      'INCORRECT: Digital signatures verify authenticity and integrity, not password storage uniqueness.'
    ],
    objectiveCodes: ['1.4'],
    tags: ['Cryptography', 'Passwords', 'Hashing'],
    threatLevel: 'high',
    logs: ['APP_AUTH: Generating random SALT for User_101', 'DB_WRITE: Storing SHA256(password + salt)'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 112 }]
  },
  {
    id: 'EXAM-A-Q80',
    domain: 'Security Operations',
    question: 'A security technician is reviewing a security log from an IPS. Log shows: "Alert: HTTP Suspicious Webdav OPTIONS Method Request... src:10.1.111.7". Which of the following can be determined?',
    options: ['Alert generated from malformed header', 'Alert generated from embedded script', 'Attacker IP is 222.43.112.74', 'Attacker IP is 10.1.111.7'],
    correctIndex: 1,
    explanation: 'The log details show "token=<script>" embedded in JSON data, indicating a Cross-Site Scripting (XSS) attempt via an embedded script.',
    rationales: [
      'INCORRECT: The alert category is "info-leak" or "Cross-Site Scripting", not a header issue.',
      'CORRECT: The log explicitly shows "<script>alert(2)</script>" in the detail field.',
      'INCORRECT: The log direction arrow or src/dst fields must be read carefully. (Context from full log usually clarifies src vs dst).',
      'INCORRECT: In the specific provided log snippet from the exam, one must parse the src/dst fields accurately.'
    ],
    objectiveCodes: ['4.9'],
    tags: ['Logs', 'IPS', 'Analysis'],
    threatLevel: 'medium',
    logs: ['IPS_ALERT: Signature "Cross-Site Scripting in JSON Data" triggered', 'PACKET_DROP: Malicious payload blocked'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 118 }]
  },
  {
    id: 'EXAM-A-Q90',
    domain: 'Security Operations',
    question: 'A company has just purchased a new application server, and the security director wants to determine if the system is secure. The system is in a test environment. Which of the following would be the BEST way to determine if any part of the system can be exploited?',
    options: ['Tabletop exercise', 'Vulnerability scanner', 'DDoS', 'Penetration test'],
    correctIndex: 3,
    explanation: 'A Penetration Test actively attempts to exploit vulnerabilities to verify if a system can actually be compromised.',
    rationales: [
      'INCORRECT: A Tabletop exercise is a discussion-based drill, not a technical test of a server.',
      'INCORRECT: A Vulnerability scanner identifies potential weaknesses but does not verify if they can be exploited.',
      'INCORRECT: DDoS tests availability, not general security exploitation.',
      'CORRECT: Pen testing goes beyond scanning to prove the risk by exploiting the flaw.'
    ],
    objectiveCodes: ['4.3'],
    tags: ['Penetration Testing', 'Vulnerability Management'],
    threatLevel: 'high',
    logs: ['PENTEST_TEAM: Initial access gained via CVE-2023-4450', 'ROOT_SHELL: Obtained on test_server_01'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 128 }]
  },
  {
    id: 'EXAM-A-Q91',
    domain: 'Security Operations',
    question: 'A system administrator is reviewing the logs of a web server and notices a large number of requests from a single IP address that are all 404 errors. Which of the following is MOST likely occurring?',
    options: ['Buffer overflow', 'Directory traversal', 'Resource exhaustion', 'Race condition'],
    correctIndex: 1,
    explanation: 'A Directory Traversal (or forced browsing) attack often generates many 404 errors as the attacker guesses filenames that do not exist while looking for sensitive files.',
    rationales: [
      'INCORRECT: Buffer overflows usually result in system crashes (500 errors) or silence, not 404s.',
      'CORRECT: Repeatedly guessing files (e.g., ../../../etc/passwd) often results in 404 Not Found if the file path is incorrect.',
      'INCORRECT: Resource exhaustion would typically manifest as timeouts (503 or 504 errors).',
      'INCORRECT: Race conditions depend on timing and typically do not generate 404 errors.'
    ],
    objectiveCodes: ['4.2'],
    tags: ['Logs', 'Web Attacks', 'Monitoring'],
    threatLevel: 'medium',
    logs: ['HTTP_ACCESS: 404 GET /admin/config.xml', 'HTTP_ACCESS: 404 GET /../../win.ini'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 130 }]
  },
  {
    id: 'EXAM-A-Q92',
    domain: 'Security Architecture',
    question: 'An organization wants to implement a solution that ensures only authorized devices can connect to the wired network. The solution should check the device\'s health status before granting access. Which of the following should be implemented?',
    options: ['WPA3', 'NAC', 'VPN', 'Captive Portal'],
    correctIndex: 1,
    explanation: 'NAC (Network Access Control) can authenticate devices (802.1X) and perform posture assessments (health checks) before allowing them on the network.',
    rationales: [
      'INCORRECT: WPA3 is a wireless encryption standard, not a wired access control solution with health checks.',
      'CORRECT: NAC provides both authentication and posture assessment (health checks) for wired/wireless networks.',
      'INCORRECT: VPN connects remote users, it is not primarily for controlling local wired port access.',
      'INCORRECT: Captive Portals are for guest authentication, usually web-based, and rarely perform deep health checks.'
    ],
    objectiveCodes: ['3.2'],
    tags: ['Network Security', 'NAC', 'Zero Trust'],
    threatLevel: 'high',
    logs: ['RADIUS: Auth Request from MAC AA:BB:CC:DD:EE:FF', 'NAC_POSTURE: Agent check failed - Antivirus disabled', 'SWITCH_PORT: VLAN 666 (Quarantine) assigned'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 131 }]
  },
  {
    id: 'EXAM-A-Q93',
    domain: 'Governance, Risk, Compliance',
    question: 'A data privacy officer is ensuring that PII is removed from a database before the data is shared with a marketing partner. The data should remain useful for analytics but individual users should not be identifiable. Which technique should be used?',
    options: ['Encryption', 'Tokenization', 'Anonymization', 'Data masking'],
    correctIndex: 2,
    explanation: 'Anonymization removes PII entirely so that the data subject cannot be re-identified, making it suitable for sharing while preserving statistical utility.',
    rationales: [
      'INCORRECT: Encryption protects confidentiality but the data is still PII (just hidden) and can be decrypted.',
      'INCORRECT: Tokenization replaces data with a token but maintains a mapping back to the original data.',
      'CORRECT: Anonymization irreversibly removes the link to the individual.',
      'INCORRECT: Data masking hides data (like showing only last 4 digits) but is usually for display purposes, not sharing datasets.'
    ],
    objectiveCodes: ['5.3'],
    tags: ['Privacy', 'Data Protection', 'Compliance'],
    threatLevel: 'low',
    logs: ['DB_EXPORT: Running sanitization script', 'DATA_PRIVACY: 50,000 records anonymized for marketing share'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 132 }]
  }
];
