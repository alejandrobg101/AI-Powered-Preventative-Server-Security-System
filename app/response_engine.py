"""
response_engine.py
------------------
Rule-based engine that:
  1. Infers a specific anomaly type from raw FlowStats + 5-tuple (infer_anomaly_type)
  2. Returns a structured Recommendation keyed on anomaly type × risk level (get_recommendation)
  3. Formats a human-readable response block for console output (format_response_block)

Anomaly-type inference uses ordered rules applied to raw flow attributes
(flag counts, ports, packet rates, byte volumes, flow duration) — no ML involved.
The knowledge base covers the attack families present in CICIDS-2017 plus
common variants seen in real environments.
"""

from __future__ import annotations

from dataclasses import dataclass

# ─────────────────────────────────────────────────────────────
# ANOMALY TYPE CONSTANTS
# ─────────────────────────────────────────────────────────────
SYN_FLOOD         = "SYN_FLOOD"
UDP_FLOOD         = "UDP_FLOOD"
ICMP_FLOOD        = "ICMP_FLOOD"
PORT_SCAN         = "PORT_SCAN"
SSH_BRUTE_FORCE   = "SSH_BRUTE_FORCE"
FTP_BRUTE_FORCE   = "FTP_BRUTE_FORCE"
HTTP_SLOWLORIS    = "HTTP_SLOWLORIS"
WEB_ATTACK        = "WEB_ATTACK"
DNS_AMPLIFICATION = "DNS_AMPLIFICATION"
GENERIC_TCP       = "GENERIC_TCP_ANOMALY"
GENERIC_UDP       = "GENERIC_UDP_ANOMALY"
GENERIC_ICMP      = "GENERIC_ICMP_ANOMALY"
UNKNOWN           = "UNKNOWN_ANOMALY"

ALL_TYPES = (
    SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, PORT_SCAN,
    SSH_BRUTE_FORCE, FTP_BRUTE_FORCE, HTTP_SLOWLORIS, WEB_ATTACK,
    DNS_AMPLIFICATION, GENERIC_TCP, GENERIC_UDP, GENERIC_ICMP, UNKNOWN,
)


# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Recommendation:
    anomaly_type: str
    description: str               # human-readable threat description
    summary: str                   # concise, DB-ready action (≤140 chars)
    actions: tuple[str, ...]       # ordered mitigation steps
    escalate: bool                 # True for High / Critical


# ─────────────────────────────────────────────────────────────
# KNOWLEDGE BASE
# Each entry has:
#   description   – threat description for console
#   Medium/High/Critical – concise summary keyed by risk name
#   actions       – ordered steps (placeholder <SRC_IP> replaced at call site)
# ─────────────────────────────────────────────────────────────
_KB: dict[str, dict] = {
    SYN_FLOOD: {
        "description": "TCP SYN flood — possible volumetric DDoS exhausting server connection table",
        "Medium":   "Rate-limit inbound SYN packets; enable SYN cookies on target host.",
        "High":     "Block source IP at firewall; enable SYN cookies; alert on-call NOC.",
        "Critical": "ESCALATE: Null-route source via upstream ISP; activate DDoS mitigation; page NOC.",
        "actions": (
            "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
            "Rate-limit SYN: iptables -A INPUT -p tcp --syn -m limit --limit 5/s --limit-burst 10 -j ACCEPT",
            "Block source: iptables -A INPUT -s <SRC_IP> -j DROP",
            "Reduce retries: sysctl -w net.ipv4.tcp_syn_retries=2",
            "Contact upstream ISP for BGP null-routing if flood persists",
        ),
    },
    UDP_FLOOD: {
        "description": "UDP flood — high-volume UDP traffic targeting service disruption",
        "Medium":   "Rate-limit UDP from source; verify no legitimate service on target port.",
        "High":     "Block source IP; apply netfilter rate limit on UDP ingress.",
        "Critical": "ESCALATE: Activate scrubbing centre; block source; alert NOC.",
        "actions": (
            "Rate-limit UDP: iptables -A INPUT -p udp -m limit --limit 100/s -j ACCEPT",
            "Block source: iptables -A INPUT -s <SRC_IP> -p udp -j DROP",
            "Audit open UDP services (NTP, Memcached, SSDP) that can be abused as amplifiers",
            "Verify BCP38 egress filtering to prevent spoofed flood traffic from your network",
        ),
    },
    ICMP_FLOOD: {
        "description": "ICMP flood — high-rate ping flood or Smurf-style amplification",
        "Medium":   "Rate-limit ICMP ingress; verify your network is not an amplifier.",
        "High":     "Restrict ICMP echo-request to trusted sources; block source.",
        "Critical": "ESCALATE: Block ICMP at border; verify no Smurf amplification; alert NOC.",
        "actions": (
            "Rate-limit: iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT",
            "Drop excess: iptables -A INPUT -p icmp -j DROP  (place after rate-limit rule)",
            "Disable directed broadcasts: sysctl -w net.ipv4.conf.all.accept_redirects=0",
            "Enable kernel ICMP rate limiting: sysctl -w net.ipv4.icmp_ratelimit=100",
        ),
    },
    PORT_SCAN: {
        "description": "Port scan — attacker enumerating open services for reconnaissance",
        "Medium":   "Log source IP; add to watchlist; no immediate block required.",
        "High":     "Block source for 24 h; review firewall for unnecessarily exposed services.",
        "Critical": "ESCALATE: Block source; audit exposed services; inspect logs for follow-on exploit.",
        "actions": (
            "Block scanner: iptables -A INPUT -s <SRC_IP> -j DROP",
            "Enable port-scan detection: install portsentry or psad",
            "Review open ports: nmap -sT localhost  — close anything non-essential",
            "Consider port-knocking or single-packet authorisation for sensitive services",
            "Audit recent auth logs for follow-on brute-force from same source",
        ),
    },
    SSH_BRUTE_FORCE: {
        "description": "SSH brute-force — repeated login attempts on port 22",
        "Medium":   "Verify fail2ban / SSHGuard is active; review recent auth failures.",
        "High":     "Block source IP; inspect /var/log/auth.log for successful logins.",
        "Critical": "ESCALATE: Block source; rotate SSH keys; verify no successful logins immediately.",
        "actions": (
            "Block source: iptables -A INPUT -s <SRC_IP> -p tcp --dport 22 -j DROP",
            "Check for successful logins: grep 'Accepted' /var/log/auth.log",
            "Verify fail2ban: apt install fail2ban && systemctl enable --now fail2ban",
            "Disable password auth: PasswordAuthentication no in /etc/ssh/sshd_config",
            "Move SSH to non-standard port or implement port-knocking",
            "Enforce MFA for all SSH access",
        ),
    },
    FTP_BRUTE_FORCE: {
        "description": "FTP brute-force — repeated login attempts on port 21",
        "Medium":   "Verify FTP account-lockout policy is active; review login logs.",
        "High":     "Block source IP; inspect FTP logs for successful logins.",
        "Critical": "ESCALATE: Block source; disable FTP immediately; verify no data exfiltration.",
        "actions": (
            "Block source: iptables -A INPUT -s <SRC_IP> -p tcp --dport 21 -j DROP",
            "Check FTP logs for successes: /var/log/vsftpd.log or /var/log/proftpd.log",
            "Disable FTP and migrate to SFTP (port 22) or FTPS",
            "Enable account lockout policy in FTP daemon configuration",
            "Restrict FTP access to known IPs via /etc/hosts.allow",
        ),
    },
    HTTP_SLOWLORIS: {
        "description": "Slowloris DoS — long-lived half-open HTTP connections exhausting server threads",
        "Medium":   "Check server connection count; verify request timeout limits are configured.",
        "High":     "Tighten connection timeouts; block source; check for thread exhaustion.",
        "Critical": "ESCALATE: Restart web service if unavailable; block source; engage DDoS mitigation.",
        "actions": (
            "Apache: Timeout 30, KeepAliveTimeout 5, RequestReadTimeout header=10-20",
            "nginx: client_header_timeout 10s; client_body_timeout 10s; keepalive_timeout 10s;",
            "Block source: iptables -A INPUT -s <SRC_IP> -p tcp --dport 80 -j DROP",
            "Limit per-IP connections: nginx limit_conn_zone / Apache mod_reqtimeout",
            "Deploy WAF or reverse proxy (HAProxy, Cloudflare) in front of origin server",
        ),
    },
    WEB_ATTACK: {
        "description": "Web application attack — possible SQL injection, XSS, or directory traversal",
        "Medium":   "Review WAF and application error logs for injection patterns.",
        "High":     "Block source at WAF/firewall; inspect DB and app logs for exploitation.",
        "Critical": "ESCALATE: Block source; take application offline for forensics if data is at risk.",
        "actions": (
            "Block source at WAF — add source IP to deny list",
            "Inspect error logs: /var/log/nginx/error.log or /var/log/apache2/error.log",
            "Search for SQLi: grep -iE 'union|select|insert|drop|--' access.log",
            "Search for XSS: grep -iE '<script|javascript:|onerror' access.log",
            "Update WAF ruleset (ModSecurity OWASP CRS) to latest version",
            "Run OWASP ZAP or Burp Suite to identify unpatched application vulnerabilities",
        ),
    },
    DNS_AMPLIFICATION: {
        "description": "DNS amplification — your resolver may be used as a DDoS reflector",
        "Medium":   "Verify DNS server is not an open resolver; enable response rate limiting.",
        "High":     "Disable recursion for external IPs; enable DNS RRL immediately.",
        "Critical": "ESCALATE: Block external port-53 UDP; contact upstream ISP; alert NOC.",
        "actions": (
            "Disable open recursion in BIND: allow-recursion { localnets; localhost; };",
            "Enable RRL in named.conf: rate-limit { responses-per-second 10; };",
            "Block external DNS: iptables -A INPUT -p udp --dport 53 ! -s <TRUSTED_RANGE> -j DROP",
            "Verify: dig +short test.openresolver.com TXT @<YOUR_DNS_IP>",
            "Consider dnsdist or PowerDNS recursor with RRL for production resolvers",
        ),
    },
    GENERIC_TCP: {
        "description": "Anomalous TCP flow — pattern deviates significantly from trained baseline",
        "Medium":   "Log and monitor source; investigate if pattern recurs.",
        "High":     "Investigate flow characteristics; consider temporary block of source.",
        "Critical": "ESCALATE: Block source; capture full packet trace; engage security team.",
        "actions": (
            "Capture traffic: tcpdump -i <IFACE> -w capture.pcap host <SRC_IP>",
            "Inspect for unusual flag combinations or abnormal payload sizes",
            "Cross-reference source IP with threat intelligence (AbuseIPDB, VirusTotal)",
            "Review adjacent flows and firewall logs for broader context",
        ),
    },
    GENERIC_UDP: {
        "description": "Anomalous UDP flow — pattern deviates significantly from trained baseline",
        "Medium":   "Log source; verify target service is behaving normally.",
        "High":     "Rate-limit UDP from source; investigate service availability.",
        "Critical": "ESCALATE: Block source UDP; verify service health; engage security team.",
        "actions": (
            "Rate-limit: iptables -A INPUT -s <SRC_IP> -p udp -m limit --limit 50/s -j ACCEPT",
            "Capture traffic: tcpdump -i <IFACE> -w capture.pcap host <SRC_IP> and udp",
            "Check target service health and response times",
            "Cross-reference source IP with threat intelligence feeds",
        ),
    },
    GENERIC_ICMP: {
        "description": "Anomalous ICMP traffic — unusual pattern or possible covert channel",
        "Medium":   "Log source; verify ICMP is necessary for this host pair.",
        "High":     "Rate-limit ICMP from source; inspect for covert-channel tunnelling.",
        "Critical": "ESCALATE: Block ICMP from source; inspect payloads for data exfiltration.",
        "actions": (
            "Rate-limit: iptables -A INPUT -p icmp -s <SRC_IP> -m limit --limit 2/s -j ACCEPT",
            "Inspect payloads for tunnelling: Wireshark — check ICMP echo payload content",
            "Block if ICMP is non-essential: iptables -A INPUT -p icmp -s <SRC_IP> -j DROP",
            "Check for icmptunnel or ptunnel processes on affected hosts",
        ),
    },
    UNKNOWN: {
        "description": "Unknown anomaly — reconstruction error exceeds threshold, type unclassified",
        "Medium":   "Log event; monitor for recurring patterns from same source.",
        "High":     "Capture traffic for manual analysis; review with security team.",
        "Critical": "ESCALATE: Block source; engage security team for forensic analysis.",
        "actions": (
            "Capture traffic: tcpdump -i <IFACE> -w anomaly.pcap host <SRC_IP>",
            "Run diagnose_features.py for per-feature reconstruction error breakdown",
            "Cross-reference source IP with threat intelligence databases (AbuseIPDB, Shodan)",
            "Review adjacent flows in threat_memory.db for context",
        ),
    },
}


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────

def infer_anomaly_type(flow, key: tuple) -> str:
    """Map raw FlowStats + 5-tuple to an anomaly type constant using ordered rules.

    Rules are evaluated top-to-bottom; first match wins.  The flow argument must
    expose: .syn .ack .fwd_pkts .bwd_pkts .fwd_bytes .bwd_bytes .start_ts .last_ts
    """
    proto    = key[4]       # 6=TCP, 17=UDP, 1=ICMP
    src_port = key[2]
    dst_port = key[3]

    duration_s = max(flow.last_ts - flow.start_ts, 1e-9)
    total_pkts = flow.fwd_pkts + flow.bwd_pkts
    pkt_rate   = total_pkts / duration_s         # packets per second

    # ── ICMP ─────────────────────────────────────────────────
    if proto == 1:
        return ICMP_FLOOD if pkt_rate > 50 else GENERIC_ICMP

    # ── UDP ──────────────────────────────────────────────────
    if proto == 17:
        fwd_b = sum(flow.fwd_bytes)
        bwd_b = sum(flow.bwd_bytes)
        if (dst_port == 53 or src_port == 53) and bwd_b > 0 and bwd_b > fwd_b * 5:
            return DNS_AMPLIFICATION
        if pkt_rate > 100:
            return UDP_FLOOD
        return GENERIC_UDP

    # ── TCP ──────────────────────────────────────────────────
    if proto == 6:
        # SYN flood: disproportionate SYN count vs ACK count
        if flow.syn >= 5 and (flow.ack == 0 or flow.syn >= flow.ack * 3):
            return SYN_FLOOD

        # Service-specific brute force (check both ports — direction is normalised)
        if 22 in (src_port, dst_port):
            return SSH_BRUTE_FORCE
        if 21 in (src_port, dst_port):
            return FTP_BRUTE_FORCE

        # HTTP / HTTPS attacks
        _web = {80, 443, 8080, 8443}
        if dst_port in _web or src_port in _web:
            # Slowloris: long-lived, almost no packets
            if duration_s > 30 and pkt_rate < 1.0:
                return HTTP_SLOWLORIS
            return WEB_ATTACK

        # Port scan: ephemeral, one-sided, no data transferred
        if duration_s < 5.0 and total_pkts <= 6 and flow.bwd_pkts == 0:
            return PORT_SCAN

        return GENERIC_TCP

    return UNKNOWN


def get_recommendation(anomaly_type: str, risk_name: str) -> Recommendation:
    """Return a Recommendation for the given anomaly type and risk level name.

    risk_name should be one of: 'Low', 'Medium', 'High', 'Critical'.
    Low-risk flows are not typically passed here, but are handled gracefully.
    """
    entry = _KB.get(anomaly_type, _KB[UNKNOWN])
    summary = entry.get(risk_name) or entry["Medium"]
    escalate = risk_name in ("High", "Critical")
    return Recommendation(
        anomaly_type=anomaly_type,
        description=entry["description"],
        summary=summary,
        actions=entry["actions"],
        escalate=escalate,
    )


def format_response_block(rec: Recommendation, src_ip: str) -> str:
    """Return a formatted multi-line console string with the full recommendation."""
    lines = [
        f"  +-- Response ------------------------------------------------",
        f"  |  Type   : {rec.anomaly_type}",
        f"  |  Threat : {rec.description}",
        f"  |  Action : {rec.summary}",
        f"  |  Steps  :",
    ]
    for i, step in enumerate(rec.actions, 1):
        line = step.replace("<SRC_IP>", src_ip)
        lines.append(f"  |    {i}. {line}")
    lines.append("  +-----------------------------------------------------------")
    return "\n".join(lines)
