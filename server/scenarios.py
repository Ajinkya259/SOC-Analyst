"""
Scenario database for the Cybersecurity Threat Response Agent.

25 realistic security alert scenarios based on real-world SOC incidents, threat
intel feeds, and documented attack campaigns. Each scenario includes full
investigation data and deterministic ground truth for grading.

Categories: Phishing (6), Suspicious Login (6), Malware (5),
            Data Exfiltration (4), Brute Force (4)
"""

from server._scenarios_phishing import PHISHING_SCENARIOS
from server._scenarios_login import LOGIN_SCENARIOS
from server._scenarios_malware import MALWARE_SCENARIOS
from server._scenarios_exfil_brute import EXFIL_BRUTE_SCENARIOS

INVESTIGATION_ACTIONS = [
    "check_user_profile",
    "check_login_history",
    "check_ip_reputation",
    "check_device_info",
    "check_email_headers",
    "check_file_analysis",
    "check_network_logs",
    "check_threat_intel",
]

DECISION_ACTIONS = [
    "classify_alert",
    "assign_severity",
]

RESPONSE_ACTIONS = [
    "block_ip",
    "block_sender_ip",
    "disable_user_account",
    "reset_user_password",
    "isolate_device",
    "quarantine_email",
    "quarantine_file",
    "send_employee_alert",
    "notify_manager",
    "escalate_to_tier2",
]

TERMINAL_ACTIONS = [
    "close_ticket_true_positive",
    "close_ticket_false_positive",
]

ALL_ACTIONS = INVESTIGATION_ACTIONS + DECISION_ACTIONS + RESPONSE_ACTIONS + TERMINAL_ACTIONS

# Actions only available for certain alert types
ALERT_SPECIFIC_ACTIONS = {
    "check_email_headers": ["phishing"],
    "check_file_analysis": ["malware_download"],
}


SCENARIOS = [
    # ─────────────────────────────────────────────────────────────────
    # PH-01: Obvious Phishing — True Positive, Easy
    # ─────────────────────────────────────────────────────────────────
    {
        "id": "PH-01",
        "difficulty": "easy",
        "alert": {
            "ticket_id": "INC-2024-00142",
            "timestamp": "2024-01-15T14:23:00Z",
            "source_tool": "Microsoft Defender",
            "alert_type": "phishing",
            "severity_reported": "high",
            "summary": "User clicked suspicious link in email claiming to be from Microsoft support. URL contains misspelled domain 'micros0ft-support.com'. Email flagged by Defender ATP.",
            "affected_user": "priya.sharma@acmecorp.com",
            "affected_device": "LAPTOP-PS-3201",
            "source_ip": "185.234.72.19",
        },
        "investigation_data": {
            "user_profile": {
                "name": "Priya Sharma",
                "department": "Finance",
                "role": "Senior Accountant",
                "hire_date": "2021-06-15",
                "risk_score": "low",
                "manager": "vikram.mehta@acmecorp.com",
                "access_level": "standard",
                "mfa_enabled": True,
                "recent_security_training": "2023-11-01",
            },
            "login_history": {
                "entries": [
                    {"timestamp": "2024-01-15T09:01:00Z", "ip": "10.0.12.45", "location": "Office-Floor2", "device": "LAPTOP-PS-3201", "status": "success", "mfa": "passed"},
                    {"timestamp": "2024-01-14T08:55:00Z", "ip": "10.0.12.45", "location": "Office-Floor2", "device": "LAPTOP-PS-3201", "status": "success", "mfa": "passed"},
                ],
                "summary": "All logins from corporate office on registered device. No anomalies in login pattern.",
            },
            "ip_reputation": {
                "ip": "185.234.72.19",
                "abuse_score": 95,
                "country": "RU",
                "isp": "BulletProof Hosting Ltd",
                "threat_tags": ["phishing-infrastructure", "credential-harvesting", "known-botnet-c2"],
                "last_reported": "2024-01-14",
                "virustotal_detections": "12/87 engines flagged as malicious",
                "first_seen": "2023-09-20",
                "associated_domains": ["micros0ft-support.com", "0ffice365-login.com", "secure-verify.net"],
            },
            "device_info": {
                "device_id": "LAPTOP-PS-3201",
                "type": "laptop",
                "os": "Windows 11 Pro 23H2",
                "last_patch": "2024-01-10",
                "encryption": "BitLocker enabled",
                "edr_status": "Microsoft Defender active — no threats detected on device",
                "registered_owner": "priya.sharma@acmecorp.com",
                "last_scan": "2024-01-15T06:00:00Z",
            },
            "email_headers": {
                "from": "support@micros0ft-support.com",
                "reply_to": "no-reply@micros0ft-support.com",
                "sender_ip": "185.234.72.19",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "received_chain": [
                    "from mail.micros0ft-support.com (185.234.72.19)",
                    "by mx.acmecorp.com (10.0.1.5)",
                ],
                "subject": "URGENT: Your Microsoft 365 account has been compromised - Verify now",
                "url_in_body": "https://micros0ft-support.com/verify?id=priya.sharma",
                "attachment": None,
                "ssl_cert_age": "2 days (issued 2024-01-13)",
            },
            "file_analysis": None,
            "network_logs": {
                "connections": [
                    {"timestamp": "2024-01-15T14:23:15Z", "dest_ip": "185.234.72.19", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 1240, "bytes_received": 45200, "duration": "12s"},
                ],
                "dns_queries": [
                    {"timestamp": "2024-01-15T14:23:10Z", "domain": "micros0ft-support.com", "resolved_ip": "185.234.72.19"},
                ],
                "summary": "Single HTTPS connection to suspicious domain. User submitted data (1.2KB sent) — possible credential submission.",
            },
            "threat_intel": {
                "campaign": "Operation PhishNet — credential harvesting campaign targeting corporate finance departments",
                "mitre_attack": ["T1566.002 (Spearphishing Link)", "T1078 (Valid Accounts)"],
                "related_iocs": ["185.234.72.19", "micros0ft-support.com", "0ffice365-login.com"],
                "threat_actor": "FIN7-affiliated",
                "confidence": "high",
                "advisory": "Multiple organizations reported similar phishing emails in the past 48 hours targeting finance teams.",
            },
        },
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "actions": ["block_sender_ip", "quarantine_email", "reset_user_password", "send_employee_alert"],
            "explanation": "Classic phishing attack. Misspelled Microsoft domain, all email auth checks failed (SPF/DKIM/DMARC), sender IP is known phishing infrastructure with 95 abuse score, SSL cert only 2 days old. User clicked link and likely submitted credentials (1.2KB data sent). Immediate password reset required.",
        },
        "relevant_investigations": ["user_profile", "ip_reputation", "email_headers", "threat_intel"],
    },

    # ─────────────────────────────────────────────────────────────────
    # SL-02: VPN False Positive — False Positive, Easy
    # ─────────────────────────────────────────────────────────────────
    {
        "id": "SL-02",
        "difficulty": "easy",
        "alert": {
            "ticket_id": "INC-2024-00156",
            "timestamp": "2024-01-16T22:15:00Z",
            "source_tool": "Azure Sentinel",
            "alert_type": "suspicious_login",
            "severity_reported": "medium",
            "summary": "Unusual login detected for user amit.kumar@acmecorp.com from IP 103.21.58.200 (Bangalore, India) outside normal working hours. User typically logs in from corporate office.",
            "affected_user": "amit.kumar@acmecorp.com",
            "affected_device": "LAPTOP-AK-1102",
            "source_ip": "103.21.58.200",
        },
        "investigation_data": {
            "user_profile": {
                "name": "Amit Kumar",
                "department": "Engineering",
                "role": "Backend Developer",
                "hire_date": "2022-01-10",
                "risk_score": "low",
                "manager": "neha.joshi@acmecorp.com",
                "access_level": "developer",
                "mfa_enabled": True,
                "recent_security_training": "2023-12-01",
                "notes": "Approved for remote work on Fridays. Home address: Bangalore.",
            },
            "login_history": {
                "entries": [
                    {"timestamp": "2024-01-16T22:15:00Z", "ip": "103.21.58.200", "location": "Bangalore, IN", "device": "LAPTOP-AK-1102", "status": "success", "mfa": "passed"},
                    {"timestamp": "2024-01-16T09:05:00Z", "ip": "10.0.15.30", "location": "Office-Floor4", "device": "LAPTOP-AK-1102", "status": "success", "mfa": "passed"},
                    {"timestamp": "2024-01-15T09:10:00Z", "ip": "10.0.15.30", "location": "Office-Floor4", "device": "LAPTOP-AK-1102", "status": "success", "mfa": "passed"},
                    {"timestamp": "2024-01-12T20:30:00Z", "ip": "103.21.58.200", "location": "Bangalore, IN", "device": "LAPTOP-AK-1102", "status": "success", "mfa": "passed"},
                ],
                "summary": "Regular pattern: office logins on weekdays, occasional evening logins from Bangalore home IP. All from registered device with MFA.",
            },
            "ip_reputation": {
                "ip": "103.21.58.200",
                "abuse_score": 2,
                "country": "IN",
                "isp": "Jio Fiber",
                "threat_tags": [],
                "last_reported": None,
                "virustotal_detections": "0/87 engines flagged",
                "first_seen": "2020-03-15",
                "note": "Residential ISP in Bangalore. Clean reputation.",
            },
            "device_info": {
                "device_id": "LAPTOP-AK-1102",
                "type": "laptop",
                "os": "Ubuntu 22.04 LTS",
                "last_patch": "2024-01-14",
                "encryption": "LUKS enabled",
                "edr_status": "CrowdStrike Falcon active — no threats",
                "registered_owner": "amit.kumar@acmecorp.com",
                "last_scan": "2024-01-16T12:00:00Z",
            },
            "email_headers": None,
            "file_analysis": None,
            "network_logs": {
                "connections": [
                    {"timestamp": "2024-01-16T22:16:00Z", "dest_ip": "10.0.1.50", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 500, "bytes_received": 12000, "duration": "ongoing", "service": "GitLab"},
                ],
                "summary": "Normal development activity — GitLab access via corporate VPN. No unusual data transfers.",
            },
            "threat_intel": {
                "campaign": None,
                "mitre_attack": [],
                "related_iocs": [],
                "confidence": "none",
                "advisory": "No threat intelligence matches for this IP or activity pattern.",
            },
        },
        "ground_truth": {
            "classification": "false_positive",
            "severity": "low",
            "actions": [],
            "explanation": "Developer working from home in the evening. IP is residential Jio Fiber in Bangalore (user's home city), clean reputation. Same registered device, MFA passed. Login history shows this is a regular pattern (previous home login on Jan 12). Normal GitLab activity. No action needed.",
        },
        "relevant_investigations": ["user_profile", "login_history", "ip_reputation", "device_info"],
    },

    # ─────────────────────────────────────────────────────────────────
    # MW-01: Trojanized Installer — True Positive, Medium
    # ─────────────────────────────────────────────────────────────────
    {
        "id": "MW-01",
        "difficulty": "medium",
        "alert": {
            "ticket_id": "INC-2024-00178",
            "timestamp": "2024-01-17T11:45:00Z",
            "source_tool": "CrowdStrike",
            "alert_type": "malware_download",
            "severity_reported": "medium",
            "summary": "Suspicious executable download detected: zoom_installer.exe from free-zoom-download.com. File flagged by CrowdStrike behavioral analysis. Process attempted to modify registry run keys.",
            "affected_user": "raj.patel@acmecorp.com",
            "affected_device": "LAPTOP-RP-1105",
            "source_ip": "203.0.113.45",
        },
        "investigation_data": {
            "user_profile": {
                "name": "Raj Patel",
                "department": "Sales",
                "role": "Account Executive",
                "hire_date": "2023-06-01",
                "risk_score": "low",
                "manager": "lisa.wang@acmecorp.com",
                "access_level": "standard",
                "mfa_enabled": True,
                "recent_security_training": "2023-10-15",
            },
            "login_history": {
                "entries": [
                    {"timestamp": "2024-01-17T09:00:00Z", "ip": "10.0.20.88", "location": "Office-Floor1", "device": "LAPTOP-RP-1105", "status": "success", "mfa": "passed"},
                ],
                "summary": "Normal login from office. No anomalies.",
            },
            "ip_reputation": {
                "ip": "203.0.113.45",
                "abuse_score": 87,
                "country": "RU",
                "isp": "BulletproofHost Ltd",
                "threat_tags": ["malware-distribution", "phishing-infrastructure"],
                "last_reported": "2024-01-16",
                "virustotal_detections": "15/87 engines flagged hosting domain as malicious",
                "first_seen": "2023-08-10",
                "associated_domains": ["free-zoom-download.com", "free-teams-install.com"],
            },
            "device_info": {
                "device_id": "LAPTOP-RP-1105",
                "type": "laptop",
                "os": "Windows 11 Pro 23H2",
                "last_patch": "2024-01-05",
                "encryption": "BitLocker enabled",
                "edr_status": "CrowdStrike active — file quarantined automatically, process terminated",
                "registered_owner": "raj.patel@acmecorp.com",
                "last_scan": "2024-01-17T06:00:00Z",
            },
            "email_headers": None,
            "file_analysis": {
                "filename": "zoom_installer.exe",
                "hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "file_size": "45.2 MB",
                "signed": False,
                "virustotal_detections": "38/72 engines detected as malicious",
                "detection_names": ["Trojan.GenericKD.46789", "Win32/Agent.NXR", "Backdoor.Cobalt"],
                "behavioral_analysis": {
                    "creates_scheduled_task": True,
                    "modifies_registry_run_key": True,
                    "beacons_to": "198.51.100.77:443",
                    "beacon_interval": "60 seconds",
                    "drops_payload": "C:\\Users\\raj.patel\\AppData\\Local\\Temp\\svchost_update.dll",
                    "persistence_mechanism": "Registry Run key + Scheduled Task",
                },
                "iocs": ["198.51.100.77", "free-zoom-download.com", "svchost_update.dll"],
                "first_seen_in_wild": "2024-01-10",
            },
            "network_logs": {
                "connections": [
                    {"timestamp": "2024-01-17T11:45:30Z", "dest_ip": "203.0.113.45", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 200, "bytes_received": 47400000, "duration": "45s", "note": "File download"},
                    {"timestamp": "2024-01-17T11:46:30Z", "dest_ip": "198.51.100.77", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 512, "bytes_received": 128, "duration": "2s", "note": "C2 beacon — blocked by CrowdStrike"},
                ],
                "summary": "File downloaded from malicious hosting, followed by immediate C2 beacon attempt (blocked by EDR).",
            },
            "threat_intel": {
                "campaign": "FakeInstaller Campaign — distributes trojanized versions of popular software via SEO poisoning",
                "mitre_attack": ["T1204.002 (User Execution: Malicious File)", "T1547.001 (Registry Run Keys)", "T1053 (Scheduled Task)", "T1071.001 (Web Protocols for C2)"],
                "related_iocs": ["198.51.100.77", "203.0.113.45", "free-zoom-download.com", "free-teams-install.com"],
                "threat_actor": "TA505",
                "confidence": "high",
                "advisory": "Active campaign since Jan 2024. Trojanized installers for Zoom, Teams, Slack distributed via SEO-poisoned search results.",
            },
        },
        "ground_truth": {
            "classification": "true_positive",
            "severity": "high",
            "actions": ["quarantine_file", "block_ip", "isolate_device", "send_employee_alert", "escalate_to_tier2"],
            "explanation": "User downloaded trojanized Zoom installer from fake site. File has 38/72 VT detections, attempts registry persistence and C2 beacon. CrowdStrike quarantined the file and blocked C2 beacon, but device should be isolated for full forensic investigation. Block malware distribution IP and C2 IP. Escalate for threat hunting across org.",
        },
        "relevant_investigations": ["file_analysis", "ip_reputation", "device_info", "network_logs", "threat_intel"],
    },

    # ─────────────────────────────────────────────────────────────────
    # DE-02: Cloud Backup Sync — False Positive, Easy
    # ─────────────────────────────────────────────────────────────────
    {
        "id": "DE-02",
        "difficulty": "easy",
        "alert": {
            "ticket_id": "INC-2024-00195",
            "timestamp": "2024-01-18T15:30:00Z",
            "source_tool": "Zscaler",
            "alert_type": "data_exfiltration",
            "severity_reported": "high",
            "summary": "Unusual data upload detected: 2.3 GB transferred to cloud storage endpoint by user meera.reddy@acmecorp.com within 30 minutes. Triggered DLP exfiltration threshold.",
            "affected_user": "meera.reddy@acmecorp.com",
            "affected_device": "DESKTOP-MR-0501",
            "source_ip": "10.0.8.112",
        },
        "investigation_data": {
            "user_profile": {
                "name": "Meera Reddy",
                "department": "Marketing",
                "role": "Content Manager",
                "hire_date": "2020-09-01",
                "risk_score": "low",
                "manager": "arjun.nair@acmecorp.com",
                "access_level": "standard",
                "mfa_enabled": True,
                "recent_security_training": "2023-11-15",
                "notes": "No HR flags. Long-tenured employee.",
            },
            "login_history": {
                "entries": [
                    {"timestamp": "2024-01-18T09:00:00Z", "ip": "10.0.8.112", "location": "Office-Floor3", "device": "DESKTOP-MR-0501", "status": "success", "mfa": "passed"},
                ],
                "summary": "Normal office login. No anomalies.",
            },
            "ip_reputation": {
                "ip": "10.0.8.112",
                "abuse_score": 0,
                "country": "Internal",
                "isp": "AcmeCorp Internal Network",
                "threat_tags": [],
                "note": "Internal corporate IP address.",
            },
            "device_info": {
                "device_id": "DESKTOP-MR-0501",
                "type": "desktop",
                "os": "Windows 11 Pro 23H2",
                "last_patch": "2024-01-12",
                "encryption": "BitLocker enabled",
                "edr_status": "CrowdStrike active — no threats",
                "registered_owner": "meera.reddy@acmecorp.com",
                "last_scan": "2024-01-18T06:00:00Z",
            },
            "email_headers": None,
            "file_analysis": None,
            "network_logs": {
                "connections": [
                    {"timestamp": "2024-01-18T15:05:00Z", "dest_ip": "13.107.42.11", "dest_port": 443, "protocol": "HTTPS", "bytes_sent": 2300000000, "bytes_received": 50000, "duration": "25m", "service": "OneDrive for Business"},
                ],
                "dns_queries": [
                    {"timestamp": "2024-01-18T15:04:55Z", "domain": "onedrive.live.com", "resolved_ip": "13.107.42.11"},
                ],
                "summary": "Large upload to OneDrive for Business (Microsoft 365 corporate tenant). This is the company-approved cloud storage solution.",
            },
            "threat_intel": {
                "campaign": None,
                "mitre_attack": [],
                "related_iocs": [],
                "confidence": "none",
                "advisory": "No threat intelligence matches. Destination is Microsoft OneDrive corporate tenant.",
            },
        },
        "ground_truth": {
            "classification": "false_positive",
            "severity": "low",
            "actions": [],
            "explanation": "Marketing content manager syncing files to company OneDrive. The 2.3GB is consistent with marketing assets (images, videos, presentations). Destination is the corporate Microsoft 365 tenant, not a personal or external service. Normal business activity triggered DLP volume threshold.",
        },
        "relevant_investigations": ["user_profile", "network_logs", "device_info"],
    },

    # ─────────────────────────────────────────────────────────────────
    # BF-01: SSH Brute Force — True Positive, Easy
    # ─────────────────────────────────────────────────────────────────
    {
        "id": "BF-01",
        "difficulty": "easy",
        "alert": {
            "ticket_id": "INC-2024-00210",
            "timestamp": "2024-01-19T03:12:00Z",
            "source_tool": "Checkpoint",
            "alert_type": "brute_force",
            "severity_reported": "high",
            "summary": "5,247 failed SSH login attempts detected from single external IP 45.33.32.100 targeting bastion host 10.0.1.100 in the last 10 minutes. Automated attack pattern detected.",
            "affected_user": "root@bastion-prod-01",
            "affected_device": "bastion-prod-01",
            "source_ip": "45.33.32.100",
        },
        "investigation_data": {
            "user_profile": {
                "name": "root (system account)",
                "department": "Infrastructure",
                "role": "Bastion Host System Account",
                "hire_date": "N/A",
                "risk_score": "high",
                "manager": "devops-team@acmecorp.com",
                "access_level": "privileged",
                "mfa_enabled": True,
                "notes": "Root SSH login is disabled. Key-based auth only. Bastion host for production environment access.",
            },
            "login_history": {
                "entries": [
                    {"timestamp": "2024-01-19T03:02:00Z", "ip": "45.33.32.100", "status": "failed", "count": 5247, "method": "password", "target_users": ["root", "admin", "ubuntu", "deploy", "jenkins"]},
                ],
                "summary": "5,247 failed attempts in 10 minutes. All password-based (key auth required). Targeted common usernames. No successful logins from this IP.",
            },
            "ip_reputation": {
                "ip": "45.33.32.100",
                "abuse_score": 100,
                "country": "US",
                "isp": "Linode LLC",
                "threat_tags": ["ssh-brute-force", "scanner", "known-attacker"],
                "last_reported": "2024-01-19",
                "virustotal_detections": "8/87 engines flagged",
                "first_seen": "2023-06-01",
                "note": "This IP has been reported 2,340 times for SSH brute force attacks in the past 90 days on AbuseIPDB.",
            },
            "device_info": {
                "device_id": "bastion-prod-01",
                "type": "server",
                "os": "Ubuntu 22.04 LTS",
                "last_patch": "2024-01-15",
                "encryption": "Full disk encryption",
                "edr_status": "CrowdStrike Falcon active — no compromise detected",
                "registered_owner": "devops-team@acmecorp.com",
                "ssh_config": "PasswordAuthentication no, PermitRootLogin no, MaxAuthTries 3",
            },
            "email_headers": None,
            "file_analysis": None,
            "network_logs": {
                "connections": [
                    {"timestamp": "2024-01-19T03:02:00Z", "src_ip": "45.33.32.100", "dest_ip": "10.0.1.100", "dest_port": 22, "protocol": "SSH", "connection_count": 5247, "duration": "10m", "status": "all rejected"},
                ],
                "summary": "Massive SSH connection attempt volume from single IP. All connections rejected at authentication stage. No successful connections.",
            },
            "threat_intel": {
                "campaign": "Automated SSH credential scanning — commodity attack, no specific APT attribution",
                "mitre_attack": ["T1110.001 (Brute Force: Password Guessing)", "T1021.004 (Remote Services: SSH)"],
                "related_iocs": ["45.33.32.100"],
                "threat_actor": "Unknown — commodity scanner",
                "confidence": "high",
                "advisory": "Standard automated SSH brute force from known scanner IP. No evidence of successful compromise. Recommend blocking at firewall.",
            },
        },
        "ground_truth": {
            "classification": "true_positive",
            "severity": "medium",
            "actions": ["block_ip", "send_employee_alert"],
            "explanation": "Confirmed brute force attack from known scanner IP (abuse score 100, 2,340 prior reports). Attack was unsuccessful — SSH is key-auth only, root login disabled, and all 5,247 attempts failed. No compromise occurred. Block IP at firewall level and notify the DevOps team. Severity is medium (not high) because the attack failed and no access was gained.",
        },
        "relevant_investigations": ["ip_reputation", "login_history", "device_info", "network_logs"],
    },
] + PHISHING_SCENARIOS + LOGIN_SCENARIOS + MALWARE_SCENARIOS + EXFIL_BRUTE_SCENARIOS


def get_scenarios_by_difficulty(difficulty: str) -> list:
    """Return scenarios matching the given difficulty level."""
    return [s for s in SCENARIOS if s["difficulty"] == difficulty]
