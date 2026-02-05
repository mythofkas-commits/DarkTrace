
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
  },
  // --- INJECTED INTELLIGENCE (BATCH B) ---
  {
    id: 'EXAM-B-Q04',
    domain: 'Security Architecture',
    question: 'An organization is migrating to a cloud environment where they will manage the operating systems and applications, but the provider manages the hardware and network. Which service model are they using?',
    options: ['SaaS', 'IaaS', 'PaaS', 'FaaS'],
    correctIndex: 1,
    explanation: 'In Infrastructure as a Service (IaaS), the customer manages the OS, apps, and data, while the provider manages the physical hardware, virtualization, and network.',
    rationales: [
      'INCORRECT: In SaaS, the provider manages everything including the application (e.g., Salesforce).',
      'CORRECT: IaaS gives the customer control starting from the Operating System layer.',
      'INCORRECT: In PaaS, the provider manages the OS and runtime, the customer just deploys code.',
      'INCORRECT: FaaS (Function as a Service) is serverless; the customer only manages individual functions.'
    ],
    objectiveCodes: ['3.1'],
    tags: ['Cloud', 'IaaS', 'Architecture'],
    threatLevel: 'low',
    logs: ['CLOUD_API: Provisioning EC2 Instance type t3.large', 'USER_ACTION: Uploading Custom AMI'],
    refs: [{ source: 'Practice Exams', section: 'Exam B', page: 12 }]
  },
  {
    id: 'EXAM-B-Q11',
    domain: 'Security Operations',
    question: 'A security analyst needs to ensure that deleted files on a hard drive cannot be recovered by third-party forensics tools before the drive is donated to charity. Which method should be used?',
    options: ['Standard formatting', 'Degaussing', 'Pulverizing', 'Wiping'],
    correctIndex: 3,
    explanation: 'Wiping (or sanitization) involves overwriting the media with random data multiple times to prevent recovery, while keeping the drive functional for reuse.',
    rationales: [
      'INCORRECT: Formatting removes pointers but data remains on the disk.',
      'INCORRECT: Degaussing destroys the drive magnetically, making it unusable (cannot be donated).',
      'INCORRECT: Pulverizing physically destroys the drive (cannot be donated).',
      'CORRECT: Wiping cleans the data while preserving the hardware for donation.'
    ],
    objectiveCodes: ['5.4'],
    tags: ['Data Destruction', 'Sanitization', 'Hardware'],
    threatLevel: 'low',
    logs: ['DISK_UTIL: Initiating DoD 5220.22-M 3-pass overwrite', 'STATUS: Sector 0-999999 overwritten'],
    refs: [{ source: 'Practice Exams', section: 'Exam B', page: 19 }]
  },
  {
    id: 'EXAM-B-Q15',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A user receives an SMS message claiming their bank account is locked and asking them to click a link to verify their identity. What type of attack is this?',
    options: ['Vishing', 'Smishing', 'Phishing', 'Spear phishing'],
    correctIndex: 1,
    explanation: 'Smishing is Phishing conducted via SMS (Short Message Service).',
    rationales: [
      'INCORRECT: Vishing involves voice calls.',
      'CORRECT: Smishing targets users via text messages.',
      'INCORRECT: Phishing is the general term, but Smishing is the specific correct answer for SMS.',
      'INCORRECT: Spear phishing targets a specific individual or organization.'
    ],
    objectiveCodes: ['2.1'],
    tags: ['Social Engineering', 'Mobile', 'Attacks'],
    threatLevel: 'medium',
    logs: ['SMS_GATEWAY: Malicious link detected in inbound text', 'URL_FILTER: Blocked domain "bank-verify-secure.com"'],
    refs: [{ source: 'Practice Exams', section: 'Exam B', page: 22 }]
  },
  {
    id: 'EXAM-B-Q22',
    domain: 'Security Architecture',
    question: 'Which of the following concepts describes a network architecture where no device or user is trusted by default, regardless of whether they are inside or outside the network perimeter?',
    options: ['Defense in Depth', 'Zero Trust', 'Air Gap', 'VPN'],
    correctIndex: 1,
    explanation: 'Zero Trust architecture assumes that the network is already compromised and requires continuous verification of every user, device, and application request.',
    rationales: [
      'INCORRECT: Defense in Depth uses layers, but often still implies a trusted internal zone.',
      'CORRECT: Zero Trust eliminates the concept of a trusted internal network.',
      'INCORRECT: Air Gap physically separates networks, which is a specific control, not the Zero Trust philosophy.',
      'INCORRECT: VPN provides a tunnel but often grants broad access once connected.'
    ],
    objectiveCodes: ['3.2'],
    tags: ['Zero Trust', 'Architecture', 'Modern Security'],
    threatLevel: 'high',
    logs: ['ZTNA_GATEWAY: User identity verified but device health check failed', 'ACCESS_DENIED: Policy "No-Trust" enforced'],
    refs: [{ source: 'Practice Exams', section: 'Exam B', page: 28 }]
  },
  {
    id: 'EXAM-B-Q29',
    domain: 'Security Operations',
    question: 'During a forensic investigation, which of the following represents the correct order of volatility (from most volatile to least)?',
    options: ['Disk, RAM, CPU Cache, Archival Media', 'CPU Cache, RAM, Swap/Page File, Hard Drive', 'RAM, CPU Cache, Hard Drive, Swap/Page File', 'Hard Drive, RAM, CPU Cache, Swap/Page File'],
    correctIndex: 1,
    explanation: 'The order of volatility dictates collecting data that disappears fastest first: CPU Registers/Cache -> RAM -> Swap/Page File -> Hard Drive -> Archival Media.',
    rationales: [
      'INCORRECT: Disk is less volatile than RAM.',
      'CORRECT: CPU Cache vanishes instantly without power; RAM vanishes quickly; Swap persists slightly longer; HDD persists without power.',
      'INCORRECT: CPU Cache is more volatile than RAM.',
      'INCORRECT: Hard Drive is the least volatile of the primary components.'
    ],
    objectiveCodes: ['4.5'],
    tags: ['Forensics', 'Incident Response'],
    threatLevel: 'medium',
    logs: ['IR_PROCEDURE: Capturing CPU registers...', 'IR_PROCEDURE: Dumping RAM to evidence drive'],
    refs: [{ source: 'Practice Exams', section: 'Exam B', page: 33 }]
  },
  {
    id: 'EXAM-C-Q03',
    domain: 'Governance, Risk, Compliance',
    question: 'A European customer requests that their personal data be completely removed from a company\'s systems. Which regulation guarantees this right?',
    options: ['PCI DSS', 'HIPAA', 'GDPR', 'SOX'],
    correctIndex: 2,
    explanation: 'GDPR (General Data Protection Regulation) includes the "Right to Erasure" (or Right to be Forgotten), allowing data subjects to demand deletion of their data.',
    rationales: [
      'INCORRECT: PCI DSS governs credit card security.',
      'INCORRECT: HIPAA governs US healthcare data.',
      'CORRECT: GDPR Article 17 defines the Right to Erasure.',
      'INCORRECT: SOX governs US corporate financial reporting.'
    ],
    objectiveCodes: ['5.3'],
    tags: ['Compliance', 'GDPR', 'Privacy'],
    threatLevel: 'low',
    logs: ['COMPLIANCE_TICKET: Article 17 Request received', 'DB_ADMIN: Executing delete_user_pii script'],
    refs: [{ source: 'Practice Exams', section: 'Exam C', page: 8 }]
  },
  {
    id: 'EXAM-C-Q12',
    domain: 'Security Architecture',
    question: 'Which tool is primarily used to monitor and enforce security policies for cloud-based applications (SaaS), such as detecting sensitive data uploads to unauthorized personal cloud storage?',
    options: ['WAF', 'NGFW', 'CASB', 'HIDS'],
    correctIndex: 2,
    explanation: 'A CASB (Cloud Access Security Broker) sits between on-prem users and cloud applications to enforce policy, visible, and data security (DLP).',
    rationales: [
      'INCORRECT: WAF protects web applications from inbound attacks (like SQLi).',
      'INCORRECT: NGFW is a network firewall, though it has some app control, CASB is specific to Cloud/SaaS policy.',
      'CORRECT: CASB is the specialized tool for Shadow IT and SaaS control.',
      'INCORRECT: HIDS monitors a specific host, not cloud traffic.'
    ],
    objectiveCodes: ['3.4'],
    tags: ['Cloud', 'CASB', 'DLP'],
    threatLevel: 'high',
    logs: ['CASB_ALERT: User uploading "confidential_project.pdf" to Personal Dropbox', 'ACTION: Blocked by DLP Policy'],
    refs: [{ source: 'Practice Exams', section: 'Exam C', page: 15 }]
  },
  {
    id: 'EXAM-C-Q19',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker sets up a fake Wi-Fi access point with the same SSID as the corporate network to intercept credentials. What is this attack called?',
    options: ['Evil Twin', 'Rogue Access Point', 'Jamming', 'Bluejacking'],
    correctIndex: 0,
    explanation: 'An Evil Twin is a specific type of Rogue AP that mimics a legitimate network (same SSID) to trick users into connecting.',
    rationales: [
      'CORRECT: Evil Twin mimics the SSID to deceive users.',
      'INCORRECT: A Rogue AP is any unauthorized AP, but "Evil Twin" specifically implies the mimicking of a legitimate network.',
      'INCORRECT: Jamming is a DoS attack against wireless frequencies.',
      'INCORRECT: Bluejacking is sending unsolicited messages via Bluetooth.'
    ],
    objectiveCodes: ['2.3'],
    tags: ['Wireless', 'Attacks', 'WiFi'],
    threatLevel: 'medium',
    logs: ['WIDS_ALERT: Duplicate SSID "Corp_Guest" detected at -40dBm', 'NETWORK_OPS: Disassociating clients from BSSID AA:AA:AA:AA:AA:AA'],
    refs: [{ source: 'Practice Exams', section: 'Exam C', page: 24 }]
  },
  {
    id: 'EXAM-C-Q25',
    domain: 'General Security Concepts',
    question: 'Which cryptographic property ensures that a message has not been altered in transit?',
    options: ['Confidentiality', 'Integrity', 'Availability', 'Non-repudiation'],
    correctIndex: 1,
    explanation: 'Integrity ensures that data remains unchanged during storage or transit, typically achieved via hashing.',
    rationales: [
      'INCORRECT: Confidentiality ensures data is not read by unauthorized parties (Encryption).',
      'CORRECT: Integrity checks (hashes) verify data has not changed.',
      'INCORRECT: Availability ensures systems are up and running.',
      'INCORRECT: Non-repudiation prevents a sender from denying they sent the message.'
    ],
    objectiveCodes: ['1.2'],
    tags: ['Cryptography', 'CIA Triad'],
    threatLevel: 'low',
    logs: ['HASH_CHECK: SHA-256 mismatch on downloaded file', 'ALERT: Integrity violation detected'],
    refs: [{ source: 'Practice Exams', section: 'Exam C', page: 30 }]
  },
  {
    id: 'EXAM-D-Q04',
    domain: 'Security Architecture',
    question: 'A server room requires high security. The door uses a smart card, but users also need to enter a PIN. What type of authentication is this?',
    options: ['Something you know', 'Single-factor', 'Multifactor', 'Something you are'],
    correctIndex: 2,
    explanation: 'Multifactor Authentication (MFA) requires two or more different factors. Smart card (Something you have) + PIN (Something you know) = MFA.',
    rationales: [
      'INCORRECT: "Something you know" is just one part (the PIN).',
      'INCORRECT: Single-factor would be just a PIN or just a card.',
      'CORRECT: It combines two distinct factors (Have + Know).',
      'INCORRECT: "Something you are" refers to biometrics.'
    ],
    objectiveCodes: ['3.3'],
    tags: ['IAM', 'MFA', 'Authentication'],
    threatLevel: 'medium',
    logs: ['DOOR_ACCESS: Card ID 88321 presented', 'AUTH_STEP: PIN verification successful'],
    refs: [{ source: 'Practice Exams', section: 'Exam D', page: 5 }]
  },
  {
    id: 'EXAM-D-Q09',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which type of malware resides only in memory (RAM) and uses legitimate system tools like PowerShell to execute malicious code, avoiding disk detection?',
    options: ['Rootkit', 'Fileless malware', 'Trojan', 'Worm'],
    correctIndex: 1,
    explanation: 'Fileless malware operates in memory and leverages "Living off the Land" (LotL) binaries (like PowerShell, WMI) rather than dropping executable files on the disk.',
    rationales: [
      'INCORRECT: Rootkits hide deep in the OS but usually exist as files/drivers.',
      'CORRECT: Fileless malware avoids the disk to bypass traditional antivirus.',
      'INCORRECT: Trojans are malicious programs disguised as legitimate software.',
      'INCORRECT: Worms self-replicate across networks.'
    ],
    objectiveCodes: ['2.1'],
    tags: ['Malware', 'PowerShell', 'Advanced Threats'],
    threatLevel: 'critical',
    logs: ['EDR_ALERT: Suspicious PowerShell execution', 'CMD_LINE: powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient)...'],
    refs: [{ source: 'Practice Exams', section: 'Exam D', page: 14 }]
  },
  {
    id: 'EXAM-D-Q18',
    domain: 'General Security Concepts',
    question: 'To prevent signal emanations from allowing an attacker to reconstruct video from a monitor through a wall, the organization installs copper shielding in the walls. What is this implementation called?',
    options: ['Air gap', 'Faraday cage', 'DMZ', 'Hot aisle'],
    correctIndex: 1,
    explanation: 'A Faraday cage is a continuous conductive enclosure used to block electromagnetic fields (RF signals).',
    rationales: [
      'INCORRECT: Air gap is a network isolation technique.',
      'CORRECT: Faraday cages block EM/RF signals (TEMPEST).',
      'INCORRECT: DMZ is a network segment for public facing services.',
      'INCORRECT: Hot aisle is a cooling configuration in a data center.'
    ],
    objectiveCodes: ['1.1'],
    tags: ['Physical Security', 'Spycraft'],
    threatLevel: 'low',
    logs: ['RF_SCANNER: No signal detected inside Secure Room', 'FACILITY: SCIF construction complete'],
    refs: [{ source: 'Practice Exams', section: 'Exam D', page: 25 }]
  },
  {
    id: 'EXAM-D-Q22',
    domain: 'Security Operations',
    question: 'A security team uses a dedicated server to lure attackers. This server contains fake data and is monitored to study attacker behavior. What is this server called?',
    options: ['Jump box', 'Honeypot', 'Proxy', 'Bastion host'],
    correctIndex: 1,
    explanation: 'A Honeypot is a decoy system designed to attract attackers to detect, deflect, or study attempts to gain unauthorized access.',
    rationales: [
      'INCORRECT: Jump box is for authorized admin access.',
      'CORRECT: Honeypots are decoys.',
      'INCORRECT: Proxy relays requests for clients.',
      'INCORRECT: Bastion host is a hardened exposed server, but not necessarily a fake decoy.'
    ],
    objectiveCodes: ['4.7'],
    tags: ['Deception', 'Active Defense'],
    threatLevel: 'low',
    logs: ['HONEYPOT_01: SSH login attempt from 192.168.1.55', 'ALARM: Attacker accessing fake_passwords.txt'],
    refs: [{ source: 'Practice Exams', section: 'Exam D', page: 29 }]
  },
  {
    id: 'EXAM-E-Q02',
    domain: 'Security Architecture',
    question: 'Which access control model grants access based on strict clearance levels (e.g., Secret, Top Secret) and object labels?',
    options: ['DAC', 'RBAC', 'MAC', 'ABAC'],
    correctIndex: 2,
    explanation: 'MAC (Mandatory Access Control) uses security labels (Clearance Level) and is enforced by the OS. Users cannot change permissions.',
    rationales: [
      'INCORRECT: DAC (Discretionary) allows owners to set permissions (Windows NTFS).',
      'INCORRECT: RBAC (Role Based) grants access based on job function.',
      'CORRECT: MAC is the strictest model, used in military/government (Labels/Clearance).',
      'INCORRECT: ABAC (Attribute Based) uses policies combining attributes (Time, Location, Role).'
    ],
    objectiveCodes: ['3.3'],
    tags: ['IAM', 'Access Control', 'Military'],
    threatLevel: 'high',
    logs: ['KERNEL: Access denied. User clearance (SECRET) < Object classification (TOP SECRET)', 'AUDIT: MAC Policy Violation'],
    refs: [{ source: 'Practice Exams', section: 'Exam E', page: 4 }]
  },
  {
    id: 'EXAM-E-Q08',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'Which of the following describes an attack where an attacker injects malicious code into a website\'s input fields, which is then executed by other users\' browsers?',
    options: ['SQL Injection', 'XSS', 'CSRF', 'SSRF'],
    correctIndex: 1,
    explanation: 'XSS (Cross-Site Scripting) involves injecting client-side scripts (usually JavaScript) into web pages viewed by other users.',
    rationales: [
      'INCORRECT: SQL Injection targets the database backend.',
      'CORRECT: XSS executes in the victim\'s browser.',
      'INCORRECT: CSRF (Cross-Site Request Forgery) tricks a user into performing an action they didn\'t intend.',
      'INCORRECT: SSRF (Server-Side Request Forgery) tricks the server into making requests.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['Web Security', 'AppSec', 'OWASP'],
    threatLevel: 'medium',
    logs: ['WAF_LOG: Detected <script> tag in comments field', 'BROWSER: Blocked execution of inline script'],
    refs: [{ source: 'Practice Exams', section: 'Exam E', page: 11 }]
  }
];
