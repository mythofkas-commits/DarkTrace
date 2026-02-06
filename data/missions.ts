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
  }
];
