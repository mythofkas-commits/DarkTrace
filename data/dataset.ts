
import { Scenario } from '../types';

export const scenarios: Scenario[] = [
  // --- PRACTICE EXAM A (COMPLETION) ---
  {
    id: 'EXAM-A-Q09',
    domain: 'Security Operations',
    question: 'A security administrator has examined a server recently compromised by an attacker, and has determined the system was exploited due to a known operating system vulnerability. Which of the following would BEST describe this finding?',
    options: ['Root cause analysis', 'E-discovery', 'Risk appetite', 'Data subject'],
    correctIndex: 0,
    explanation: 'Root cause analysis is the process of identifying the fundamental cause of an issue or event (in this case, the known OS vulnerability) to prevent it from recurring[cite: 7815, 6829].',
    rationales: [
      'CORRECT: Root cause analysis identifies the specific vulnerability that allowed the compromise.',
      'INCORRECT: E-discovery refers to the identification and collection of electronic evidence for legal proceedings.',
      'INCORRECT: Risk appetite describes how much risk an organization is willing to accept.',
      'INCORRECT: Data subject refers to the individual whose personal data is being processed.'
    ],
    objectiveCodes: ['4.8'],
    tags: ['Incident Response', 'Analysis', 'Vulnerability'],
    threatLevel: 'medium',
    logs: ['INCIDENT_RPT: Root Cause = CVE-2023-9988 (Unpatched OS)', 'ACTION: Patching cycle updated'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 46 }]
  },
  {
    id: 'EXAM-A-Q10',
    domain: 'Security Architecture',
    question: 'A city is building an ambulance service network for emergency medical dispatching. Which of the following should have the highest priority?',
    options: ['Integration costs', 'Patch availability', 'System availability', 'Power usage'],
    correctIndex: 2,
    explanation: 'For emergency services like ambulance dispatching, system availability is the most critical requirement to ensure lives are not put at risk due to downtime[cite: 7830, 6829].',
    rationales: [
      'INCORRECT: Integration costs are a business concern but do not outweigh life-safety availability.',
      'INCORRECT: Patch availability is important for security but secondary to the immediate uptime requirement of 911 services.',
      'CORRECT: Availability (uptime) is the primary objective for safety-critical systems.',
      'INCORRECT: Power usage is an efficiency metric, not a mission-critical requirement.'
    ],
    objectiveCodes: ['3.4'],
    tags: ['Availability', 'Safety Critical', 'CIA Triad'],
    threatLevel: 'low',
    logs: ['SLA_MONITOR: Dispatch System Uptime < 99.999%', 'ALERT: Critical availability threshold breached'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 47 }]
  },
  {
    id: 'EXAM-A-Q11',
    domain: 'Security Operations',
    question: 'A system administrator receives a text alert when access rights are changed on a database containing private customer information. Which of the following would describe this alert?',
    options: ['Maintenance window', 'Attestation and acknowledgment', 'Automation', 'External audit'],
    correctIndex: 2,
    explanation: 'Automation allows for the immediate, programmed generation of alerts (via text/SMS) based on specific triggers, such as changes to access rights[cite: 7834, 6829].',
    rationales: [
      'INCORRECT: A maintenance window is a scheduled time for system updates.',
      'INCORRECT: Attestation is a formal verification process, typically manual or periodic.',
      'CORRECT: The automatic sending of text alerts is a form of security automation.',
      'INCORRECT: An external audit is a formal review by a third party, not a real-time alert.'
    ],
    objectiveCodes: ['4.7'],
    tags: ['Automation', 'Monitoring', 'Alerting'],
    threatLevel: 'low',
    logs: ['AUTO_BOT: Trigger "DB_Rights_Change" fired', 'SMS_OUT: "Admin access granted to User_J" sent to Admin'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 48 }]
  },
  {
    id: 'EXAM-A-Q13',
    domain: 'Governance, Risk, Compliance',
    question: 'A company creates a standard set of government reports each calendar quarter. Which of the following would describe this type of data?',
    options: ['Data in use', 'Obfuscated', 'Trade secrets', 'Regulated'],
    correctIndex: 3,
    explanation: 'Data required for government reports is controlled by laws and regulations, making it "Regulated" data (e.g., PII, PHI, financial reports)[cite: 7854, 6829].',
    rationales: [
      'INCORRECT: "Data in use" describes the state of data (in RAM), not its classification.',
      'INCORRECT: Obfuscated data has been hidden or masked.',
      'INCORRECT: Trade secrets refer to intellectual property, not necessarily government reports.',
      'CORRECT: Government reporting implies the data is subject to regulatory compliance.'
    ],
    objectiveCodes: ['5.3'],
    tags: ['Compliance', 'Data Classification', 'Governance'],
    threatLevel: 'low',
    logs: ['DATA_CLASS: Report_Q3 tagged as REGULATED', 'DLP: Upload to public cloud blocked'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 50 }]
  },
  {
    id: 'EXAM-A-Q15',
    domain: 'Security Operations',
    question: 'A security engineer is viewing a firewall log showing "Gateway Anti-Virus Alert: XPACK.A_7854 (Trojan) blocked." for traffic from an external IP to an internal host. Which of the following can be observed from this log?',
    options: ['The victim\'s IP address is 136.127.92.171', 'A download was blocked from a web server', 'A botnet DDoS attack was blocked', 'The Trojan was blocked, but the file was not'],
    correctIndex: 1,
    explanation: 'The log shows an external IP (Source) connecting to an internal IP (Destination) on port 80 (Web), and the Gateway AV blocked a Trojan. This indicates a malicious download was attempted and stopped[cite: 7881, 6829].',
    rationales: [
      'INCORRECT: 136.127.92.171 is the Source (Attacker/Server), not the victim.',
      'CORRECT: Traffic on port 80 implies a web download, which was blocked by the AV gateway.',
      'INCORRECT: A single Trojan signature does not indicate a Distributed Denial of Service (DDoS).',
      'INCORRECT: The log explicitly states "Trojan... blocked."',
    ],
    objectiveCodes: ['4.2'],
    tags: ['Logs', 'Firewall', 'Malware'],
    threatLevel: 'high',
    logs: ['FW_AV: Blocked file "invoice.exe" (Trojan) from 136.127.92.171', 'HTTP_RSP: 403 Forbidden'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 53 }]
  },
  {
    id: 'EXAM-A-Q16',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A user connects to a third-party website and receives this message: "Your connection is not private. NET::ERR_CERT_INVALID". Which of the following attacks would be the MOST likely reason for this message?',
    options: ['Brute force', 'DoS', 'On-path', 'Deauthentication'],
    correctIndex: 2,
    explanation: 'An On-path attack (Man-in-the-Middle) often involves intercepting SSL/TLS traffic, which causes certificate errors because the attacker cannot present a valid certificate for the target domain[cite: 7892, 6829].',
    rationales: [
      'INCORRECT: Brute force attacks target passwords, not SSL certificates.',
      'INCORRECT: DoS attacks stop the service but do not typically cause certificate errors.',
      'CORRECT: Intercepting HTTPS traffic breaks the chain of trust, triggering invalid certificate warnings.',
      'INCORRECT: Deauthentication kicks a user off Wi-Fi, it does not cause browser certificate errors.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['MitM', 'Encryption', 'Certificates'],
    threatLevel: 'high',
    logs: ['SSL_ERROR: Cert common name mismatch', 'ALERT: Possible ARP Spoofing detected'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 54 }]
  },
  {
    id: 'EXAM-A-Q17',
    domain: 'Security Architecture',
    question: 'Which of the following would be the BEST way to provide a website login using existing credentials from a third-party site?',
    options: ['Federation', '802.1X', 'EAP', 'SSO'],
    correctIndex: 0,
    explanation: 'Federation allows a user to use credentials from one organization (Identity Provider) to access services in another organization (Service Provider), such as "Login with Google"[cite: 7901, 6829].',
    rationales: [
      'CORRECT: Federation links identity across different security domains.',
      'INCORRECT: 802.1X is a network access control protocol, not a web login method.',
      'INCORRECT: EAP (Extensible Authentication Protocol) is used in wireless/wired networks, not web federation.',
      'INCORRECT: SSO (Single Sign-On) usually refers to internal authentication; Federation is the specific term for third-party/cross-domain auth.'
    ],
    objectiveCodes: ['3.3'],
    tags: ['IAM', 'Federation', 'OIDC'],
    threatLevel: 'low',
    logs: ['SAML_AUTH: Token received from IDP (Google)', 'ACCESS_GRANT: User authenticated via Federation'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 55 }]
  },
  {
    id: 'EXAM-A-Q19',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'An attacker calls into a company\'s help desk and pretends to be the director... stating they have forgotten their password and need it reset quickly. What kind of attack is this?',
    options: ['Social engineering', 'Supply chain', 'Watering hole', 'On-path'],
    correctIndex: 0,
    explanation: 'Social engineering relies on psychological manipulation (urgency, authority) to trick people into divulging confidential information[cite: 7922, 6829].',
    rationales: [
      'CORRECT: Impersonating a director and creating urgency is a classic social engineering tactic.',
      'INCORRECT: Supply chain attacks target vendors or software dependencies.',
      'INCORRECT: Watering hole attacks compromise websites visited by the target.',
      'INCORRECT: On-path attacks intercept network traffic.'
    ],
    objectiveCodes: ['2.2'],
    tags: ['Social Engineering', 'Vishing', 'Human Factors'],
    threatLevel: 'medium',
    logs: ['CALL_LOG: Inbound from Unknown Number', 'INCIDENT: Helpdesk reset password without verification'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 57 }]
  },
  {
    id: 'EXAM-A-Q20',
    domain: 'Governance, Risk, Compliance',
    question: 'Two companies have been working together... and would now like to qualify their partnership with a broad formal agreement. Which of the following would describe this agreement?',
    options: ['SLA', 'SOW', 'MOA', 'NDA'],
    correctIndex: 2,
    explanation: 'An MOA (Memorandum of Agreement) is a formal legal document that outlines the terms and details of a partnership or cooperation between two organizations[cite: 7928, 6829].',
    rationales: [
      'INCORRECT: SLA (Service Level Agreement) defines specific performance metrics (uptime, latency).',
      'INCORRECT: SOW (Statement of Work) defines specific project deliverables.',
      'CORRECT: MOA establishes the broad legal framework for the partnership.',
      'INCORRECT: NDA (Non-Disclosure Agreement) is solely for confidentiality.'
    ],
    objectiveCodes: ['5.4'],
    tags: ['Contracts', 'Legal', 'Third-Party Risk'],
    threatLevel: 'low',
    logs: ['LEGAL_DOC: MOA_v1.pdf signed by both parties', 'PARTNER_STATUS: Active'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 58 }]
  },
  {
    id: 'EXAM-A-Q21',
    domain: 'General Security Concepts',
    question: 'Which of the following would explain why a company would automatically add a digital signature to each outgoing email message?',
    options: ['Confidentiality', 'Integrity', 'Authentication', 'Availability'],
    correctIndex: 1,
    explanation: 'A digital signature provides Integrity (proving the message hasn\'t changed) and Non-repudiation (proving who sent it). It does not encrypt the message (Confidentiality)[cite: 7943, 6829].',
    rationales: [
      'INCORRECT: Confidentiality requires encryption, not just signing.',
      'CORRECT: Digital signatures rely on hashing to verify that the message content was not altered (Integrity).',
      'INCORRECT: While it provides authentication of the sender, Integrity is the primary technical property of the signature hash.',
      'INCORRECT: Availability is about system uptime.'
    ],
    objectiveCodes: ['1.2'],
    tags: ['Cryptography', 'Email Security', 'Integrity'],
    threatLevel: 'low',
    logs: ['EMAIL_GATEWAY: Signed message with private key', 'HASH_VERIFY: SHA256 OK'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 59 }]
  },
  {
    id: 'EXAM-A-Q22',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'The embedded OS in a company\'s time clock appliance is configured to reset... when a file system error occurs. This file system error occurs during startup, causing a constant reboot loop. What describes this?',
    options: ['Memory injection', 'Resource consumption', 'Race condition', 'Malicious update'],
    correctIndex: 2,
    explanation: 'A Race Condition occurs when the timing of events (like startup processes) causes a system glitch or failure. In this case, the error forces a reboot, which triggers the error again[cite: 7947, 6829].',
    rationales: [
      'INCORRECT: Memory injection involves inserting code into RAM.',
      'INCORRECT: Resource consumption refers to exhausting CPU/RAM (DoS).',
      'CORRECT: The loop is caused by the sequence and timing of the boot process and error handler (Race Condition).',
      'INCORRECT: There is no evidence of an update being applied.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['AppSec', 'Embedded Systems', 'Vulnerabilities'],
    threatLevel: 'medium',
    logs: ['KERNEL: Panic during boot -> Initiating Reboot', 'UPTIME: 0h 0m 12s'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 60 }]
  },
  {
    id: 'EXAM-A-Q25',
    domain: 'Security Operations',
    question: 'An internal audit has discovered four servers that have not been updated in over a year... it will take two weeks to test/deploy patches. What is the BEST immediate response?',
    options: ['Purchase cybersecurity insurance', 'Implement an exception', 'Move the servers to a protected segment', 'Hire a third-party audit'],
    correctIndex: 2,
    explanation: 'If a system cannot be patched immediately, the best Compensating Control is to isolate it (segmentation) to reduce the attack surface until the patch can be deployed[cite: 7973, 6829].',
    rationales: [
      'INCORRECT: Insurance transfers risk but does not secure the vulnerable servers.',
      'INCORRECT: Ignoring the risk via exception is dangerous for critical vulnerabilities.',
      'CORRECT: Network segmentation (VLAN/Firewall) limits access to the vulnerable systems, mitigating risk.',
      'INCORRECT: A third-party audit takes too long and doesn\'t fix the immediate danger.'
    ],
    objectiveCodes: ['4.3'],
    tags: ['Vulnerability Management', 'Compensating Controls', 'Segmentation'],
    threatLevel: 'high',
    logs: ['NETWORK_CHANGE: Moved VLAN 10 (Legacy) to VLAN 666 (Isolated)', 'ACL: Deny All Inbound except Mgmt'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 63 }]
  },
  {
    id: 'EXAM-A-Q26',
    domain: 'Governance, Risk, Compliance',
    question: 'A business manager is documenting a set of steps for processing orders if the primary Internet connection fails. Which of these would BEST describe these steps?',
    options: ['Platform diversity', 'Continuity of operations', 'Cold site recovery', 'Tabletop exercise'],
    correctIndex: 1,
    explanation: 'Continuity of Operations (COOP) planning involves creating procedures to ensure essential business functions (like processing orders) continue during a disruption[cite: 7979, 6829].',
    rationales: [
      'INCORRECT: Platform diversity refers to using different OSs to reduce common risks.',
      'CORRECT: Documenting how to work around a failure is the core of Business Continuity.',
      'INCORRECT: Cold site recovery is a disaster recovery strategy, not a specific process step document.',
      'INCORRECT: Tabletop exercise is a drill, not the documentation of the steps itself.'
    ],
    objectiveCodes: ['5.2'],
    tags: ['BCP', 'Resiliency', 'Availability'],
    threatLevel: 'low',
    logs: ['DOC_UPDATE: Updated "Offline_Order_Processing_Procedure.docx"', 'BCP_DRILL: Success'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 64 }]
  },
  {
    id: 'EXAM-A-Q27',
    domain: 'Security Architecture',
    question: 'A company would like to examine the credentials of each individual entering the data center building. Which of the following would BEST facilitate this requirement?',
    options: ['Access control vestibule', 'Video surveillance', 'Pressure sensors', 'Bollards'],
    correctIndex: 0,
    explanation: 'An access control vestibule (mantrap) allows a company to control entry by holding a person in a secure area while their credentials are verified before allowing access to the secure zone[cite: 7984, 6829].',
    rationales: [
      'CORRECT: Vestibules physically control the flow for verification.',
      'INCORRECT: Video surveillance records events but cannot physically stop or verify credentials alone.',
      'INCORRECT: Pressure sensors detect weight but do not verify credentials.',
      'INCORRECT: Bollards prevent vehicle entry, not pedestrian credential verification.'
    ],
    objectiveCodes: ['1.2'],
    tags: ['Physical Security', 'Controls'],
    threatLevel: 'low',
    logs: ['ACCESS_LOG: Vestibule Door 1 Opened', 'AUTH_CHECK: Badge Verified', 'ACCESS_LOG: Vestibule Door 2 Unlocked'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 65 }]
  },
  {
    id: 'EXAM-A-Q28',
    domain: 'General Security Concepts',
    question: 'A company stores some employee information in encrypted form, but other public details are stored as plaintext. Which of the following would BEST describe this encryption strategy?',
    options: ['Full-disk', 'Record', 'Asymmetric', 'Key escrow'],
    correctIndex: 1,
    explanation: 'Record (or column/field) level encryption allows specific pieces of sensitive data (like SSNs) to be encrypted while leaving other non-sensitive data (like names) readable for database performance[cite: 8000, 6829].',
    rationales: [
      'INCORRECT: Full-disk encryption encrypts the entire drive; you cannot have mixed plaintext/encrypted fields.',
      'CORRECT: Record/Field encryption targets specific data points.',
      'INCORRECT: Asymmetric encryption refers to the key type (Public/Private), not the storage scope.',
      'INCORRECT: Key escrow is for key recovery, not selective encryption.'
    ],
    objectiveCodes: ['1.3'],
    tags: ['Cryptography', 'Database Security', 'Data Protection'],
    threatLevel: 'low',
    logs: ['DB_CONFIG: Encrypt Column "SSN" with AES-256', 'QUERY: Select * from Employees (partial decrypt)'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 66 }]
  },
  {
    id: 'EXAM-A-Q29',
    domain: 'Security Architecture',
    question: 'A company would like to minimize database corruption if power is lost to a server. Which of the following would be the BEST strategy to follow?',
    options: ['Encryption', 'Off-site backups', 'Journaling', 'Replication'],
    correctIndex: 2,
    explanation: 'Journaling is a file system or database feature that logs changes before they are committed. If a crash occurs, the journal can be replayed to restore consistency and prevent corruption[cite: 8006, 6829].',
    rationales: [
      'INCORRECT: Encryption protects confidentiality, not integrity during a crash.',
      'INCORRECT: Off-site backups are for disaster recovery, not preventing immediate corruption.',
      'CORRECT: Journaling file systems (like NTFS, ext4) are designed to recover quickly from power failures.',
      'INCORRECT: Replication copies data; if corruption occurs, the corrupted data might be replicated.'
    ],
    objectiveCodes: ['3.4'],
    tags: ['Resiliency', 'Database', 'Integrity'],
    threatLevel: 'low',
    logs: ['FS_CHECK: Replaying Journal...', 'STATUS: File system recovered'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 67 }]
  },
  {
    id: 'EXAM-A-Q31',
    domain: 'Security Operations',
    question: 'A security engineer runs a monthly vulnerability scan. The scan doesn\'t list any vulnerabilities for Windows servers, but a significant vulnerability was announced last week and none of the servers are patched yet. Which of the following best describes this result?',
    options: ['Exploit', 'Compensating controls', 'Zero-day attack', 'False negative'],
    correctIndex: 3,
    explanation: 'A false negative occurs when a scanning tool fails to identify a vulnerability that actually exists. The scanner missed the missing patch[cite: 8028, 6829].',
    rationales: [
      'INCORRECT: An exploit is the code used to take advantage of a vulnerability.',
      'INCORRECT: Compensating controls are alternative security measures.',
      'INCORRECT: Zero-day refers to unknown/unpatched threats; here the vulnerability is known ("announced last week").',
      'CORRECT: The tool reported "Safe" when the system was actually "Vulnerable" (False Negative).'
    ],
    objectiveCodes: ['4.3'],
    tags: ['Vulnerability Management', 'Scanning', 'Metrics'],
    threatLevel: 'medium',
    logs: ['SCAN_RPT: 0 Vulnerabilities Found', 'MANUAL_CHECK: CVE-2023-XYZ is present. ALERT: Scanner outdated'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 69 }]
  },
  {
    id: 'EXAM-A-Q32',
    domain: 'Security Operations',
    question: 'An IT help desk is using automation to improve the response time for security events. Which of the following use cases would apply to this process?',
    options: ['Escalation', 'Guard rails', 'Continuous integration', 'Resource provisioning'],
    correctIndex: 0,
    explanation: 'Automated escalation ensures that critical security tickets are immediately routed to the correct higher-level teams without manual delay, improving response time[cite: 8032, 6829].',
    rationales: [
      'CORRECT: Automation can route/escalate tickets instantly based on severity.',
      'INCORRECT: Guard rails are for development/deployment limits.',
      'INCORRECT: Continuous integration is for software development.',
      'INCORRECT: Resource provisioning is for creating IT assets, not handling security events/tickets.'
    ],
    objectiveCodes: ['4.7'],
    tags: ['Automation', 'Incident Response', 'Help Desk'],
    threatLevel: 'low',
    logs: ['TICKET_SYS: Severity=Critical -> Auto-Escalate to Tier 3 Security', 'NOTIFY: PagerDuty Triggered'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 70 }]
  },
  {
    id: 'EXAM-A-Q33',
    domain: 'Security Architecture',
    question: 'A network administrator would like each user to authenticate with their corporate username and password when connecting to the company\'s wireless network. Which of the following should be configured?',
    options: ['WPA3', '802.1X', 'PSK', 'MFA'],
    correctIndex: 1,
    explanation: '802.1X (often WPA2/3-Enterprise) allows users to authenticate to a wireless network using individual credentials (RADIUS/LDAP) rather than a shared password[cite: 8038, 6829].',
    rationales: [
      'INCORRECT: WPA3 is the encryption standard, but 802.1X is the authentication mechanism for individual users.',
      'CORRECT: 802.1X provides port-based network access control using individual credentials.',
      'INCORRECT: PSK (Pre-Shared Key) uses the same password for everyone.',
      'INCORRECT: MFA is an authentication method, but 802.1X is the network protocol required to carry it.'
    ],
    objectiveCodes: ['3.2'],
    tags: ['Wireless', 'Network Security', 'IAM'],
    threatLevel: 'medium',
    logs: ['RADIUS: Access-Request User=jdoe', 'WIFI_AP: Station Authenticated via 802.1X'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 71 }]
  },
  {
    id: 'EXAM-A-Q34',
    domain: 'Security Architecture',
    question: 'A company\'s VPN service performs a posture assessment during the login process. Which of the following mitigation techniques would this describe?',
    options: ['Encryption', 'Decommissioning', 'Least privilege', 'Configuration enforcement'],
    correctIndex: 3,
    explanation: 'Posture assessment checks the device\'s health (OS version, Antivirus status) and enforces configuration requirements before allowing the connection[cite: 8044, 6829].',
    rationales: [
      'INCORRECT: Encryption protects the tunnel.',
      'INCORRECT: Decommissioning is removing assets.',
      'INCORRECT: Least privilege limits access rights.',
      'CORRECT: Configuration enforcement ensures devices meet security standards (posture) before connecting.'
    ],
    objectiveCodes: ['3.2'],
    tags: ['NAC', 'VPN', 'Endpoint Security'],
    threatLevel: 'medium',
    logs: ['VPN_GW: Posture Check Failed (Firewall Disabled)', 'ACTION: Quarantine Device'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 72 }]
  },
  {
    id: 'EXAM-A-Q35',
    domain: 'Governance, Risk, Compliance',
    question: 'A user has assigned individual rights and permissions to a file on their network drive. The user adds three additional individuals to have read-only access. Which access control model is this?',
    options: ['Discretionary', 'Mandatory', 'Attribute-based', 'Role-based'],
    correctIndex: 0,
    explanation: 'In Discretionary Access Control (DAC), the data owner (the user) has the discretion to assign permissions to others[cite: 8060, 6829].',
    rationales: [
      'CORRECT: The user (owner) is deciding who gets access.',
      'INCORRECT: Mandatory (MAC) uses system labels and users cannot change permissions.',
      'INCORRECT: ABAC uses complex attributes (location, time).',
      'INCORRECT: RBAC uses job roles, not individual user discretion.'
    ],
    objectiveCodes: ['5.4'],
    tags: ['IAM', 'Access Control', 'DAC'],
    threatLevel: 'low',
    logs: ['FS_AUDIT: User "Alice" granted READ to "Bob" on "Project.doc"', 'ACL: Updated'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 73 }]
  },
  {
    id: 'EXAM-A-Q36',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A remote user has received a text message with a link to login and confirm their upcoming work schedule. Which of the following would BEST describe this attack?',
    options: ['Brute force', 'Watering hole', 'Typosquatting', 'Smishing'],
    correctIndex: 3,
    explanation: 'Smishing (SMS Phishing) is the use of text messages to trick users into clicking malicious links or revealing info[cite: 8066, 6829].',
    rationales: [
      'INCORRECT: Brute force guesses passwords.',
      'INCORRECT: Watering hole infects a valid site visited by the target.',
      'INCORRECT: Typosquatting relies on mistyped URLs.',
      'CORRECT: The attack vector is SMS/Text.'
    ],
    objectiveCodes: ['2.2'],
    tags: ['Social Engineering', 'Phishing', 'Mobile'],
    threatLevel: 'medium',
    logs: ['MSG_FILTER: Blocked URL in SMS from unknown sender', 'THREAT_INTEL: "schedule-confirm.com" is malicious'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 74 }]
  },
  {
    id: 'EXAM-A-Q37',
    domain: 'Security Operations',
    question: 'A company is formalizing the design and deployment process used by their application programmers. Which of the following policies would apply?',
    options: ['Business continuity', 'Acceptable use policy', 'Incident response', 'Development lifecycle'],
    correctIndex: 3,
    explanation: 'The Software Development Lifecycle (SDLC) defines the formal processes for designing, developing, testing, and deploying software securely[cite: 8072, 6829].',
    rationales: [
      'INCORRECT: BCP is for outages.',
      'INCORRECT: AUP is for user behavior.',
      'INCORRECT: Incident response is for reacting to breaches.',
      'CORRECT: SDLC governs the "design and deployment process" of applications.'
    ],
    objectiveCodes: ['4.1'],
    tags: ['AppSec', 'SDLC', 'Policy'],
    threatLevel: 'low',
    logs: ['DEVOPS: Pipeline failed - Static Analysis Required by SDLC Policy', 'AUDIT: Code merged without review'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 75 }]
  },
  {
    id: 'EXAM-A-Q38',
    domain: 'Security Operations',
    question: 'A security administrator has copied a suspected malware executable from a user\'s computer and is running the program in a sandbox. Which of the following would describe this part of the incident response process?',
    options: ['Eradication', 'Preparation', 'Recovery', 'Containment'],
    correctIndex: 3,
    explanation: 'While analysis happens here, running malware in a sandbox is part of Containment (keeping it isolated while studying it) or Analysis. Given the options, Containment is the best fit for isolating the code[cite: 8077, 6829]. *Note: Some contexts might argue Analysis, but the provided key lists Containment.*',
    rationales: [
      'INCORRECT: Eradication is removing the infection.',
      'INCORRECT: Preparation is before the incident.',
      'INCORRECT: Recovery is restoring operations.',
      'CORRECT: Sandboxing isolates the threat (Containment) to prevent spread.'
    ],
    objectiveCodes: ['4.8'],
    tags: ['Incident Response', 'Malware Analysis', 'Sandboxing'],
    threatLevel: 'high',
    logs: ['SANDBOX: Executing sample.exe', 'BEHAVIOR: Network connection attempt to C2 server detected'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 76 }]
  },
  {
    id: 'EXAM-A-Q39',
    domain: 'Threats, Vulnerabilities, Mitigations',
    question: 'A server administrator at a bank has noticed a decrease in website visitors. Research shows users are being directed to a different IP address than the bank\'s web server. What is this attack?',
    options: ['Deauthentication', 'DDoS', 'Buffer overflow', 'DNS poisoning'],
    correctIndex: 3,
    explanation: 'DNS Poisoning corrupts the name resolution process, causing legitimate URLs (like bank.com) to resolve to the attacker\'s IP address instead of the real one[cite: 8093, 6829].',
    rationales: [
      'INCORRECT: Deauth is wireless.',
      'INCORRECT: DDoS slows/stops the site, it doesn\'t redirect it.',
      'INCORRECT: Buffer overflow crashes apps.',
      'CORRECT: Redirecting traffic by spoofing the IP resolution is the definition of DNS poisoning.'
    ],
    objectiveCodes: ['2.4'],
    tags: ['Network Attacks', 'DNS', 'Spoofing'],
    threatLevel: 'critical',
    logs: ['DNS_SERVER: Cache updated with invalid record', 'USER_REPORT: "Bank site looks weird"'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 77 }]
  },
  {
    id: 'EXAM-A-Q40',
    domain: 'Security Architecture',
    question: 'Which of the following considerations are MOST commonly associated with a hybrid cloud model?',
    options: ['Microservice outages', 'IoT support', 'Network protection mismatches', 'Containerization backups'],
    correctIndex: 2,
    explanation: 'A Hybrid Cloud mixes on-premise and public cloud environments. A major challenge is "Network protection mismatches," ensuring security policies are consistent across these two very different environments[cite: 8100, 6829].',
    rationales: [
      'INCORRECT: Microservice issues occur in any cloud.',
      'INCORRECT: IoT is not specific to hybrid.',
      'CORRECT: Inconsistent security controls between On-Prem and Cloud is a key hybrid risk.',
      'INCORRECT: Container backups are a general DevOps task.'
    ],
    objectiveCodes: ['3.1'],
    tags: ['Cloud', 'Hybrid', 'Architecture'],
    threatLevel: 'medium',
    logs: ['AUDIT_FAIL: AWS Security Group does not match On-Prem Firewall Rule', 'ALERT: Policy Gap Identified'],
    refs: [{ source: 'Practice Exams', section: 'Exam A', page: 78 }]
  }
];
