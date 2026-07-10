"""
NetMind — AI-Powered Network Troubleshooter
Author: Ahmed Al-Ghamdi
Description: AI assistant that diagnoses network issues from natural language,
             analyzes device logs, and generates remediation commands.
"""

import json
import datetime
import os
import sys
import urllib.request
import urllib.error

# ─────────────────────────────────────────────
# CLAUDE API CONFIGURATION
# ─────────────────────────────────────────────
# المفتاح يُقرأ من متغير بيئة ANTHROPIC_API_KEY — لا تكتبه هنا مباشرة
# مثال (Linux/Mac):  export ANTHROPIC_API_KEY="sk-ant-..."
# مثال (Windows):    setx ANTHROPIC_API_KEY "sk-ant-..."
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-6"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"


def ask_claude(prompt: str, max_tokens: int = 1024) -> str:
    """Send a prompt to Claude API and return the text response."""
    if not ANTHROPIC_API_KEY:
        return "⚠️ لم يتم إعداد مفتاح API — ضع ANTHROPIC_API_KEY كمتغير بيئة قبل التشغيل."

    headers = {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
    }
    body = {
        "model": CLAUDE_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        req = urllib.request.Request(
            CLAUDE_API_URL,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data["content"][0]["text"]
    except urllib.error.HTTPError as e:
        return f"⚠️ خطأ في الاتصال بـ Claude API: {e.code} — {e.read().decode()}"
    except Exception as e:
        return f"⚠️ خطأ غير متوقع: {str(e)}"


def generate_ai_diagnosis(description: str, device: str, log_text: str = "") -> str:
    """Use Claude to generate an intelligent diagnosis."""
    prompt = f"""أنت NetMind، مساعد ذكي متخصص في تشخيص مشاكل الشبكات.

نوع الجهاز: {device}
وصف المشكلة من المستخدم: "{description}"
{f'سجل الأحداث (Log) المرفق: {log_text}' if log_text else ''}

قدّم تشخيصاً احترافياً يتضمن:
1. نوع المشكلة بدقة
2. مستوى الخطورة (CRITICAL/HIGH/MEDIUM/LOW)
3. الأسباب المحتملة (3-5 أسباب)
4. أوامر التشخيص المناسبة لجهاز {device}
5. خطوات الحل المقترحة بالترتيب

اكتب الإجابة بالعربية والإنجليزية معاً، بشكل واضح ومنظم."""

    return ask_claude(prompt, max_tokens=1200)


def generate_ticket(description: str, diagnosis_summary: str, device: str) -> str:
    """Use Claude to generate a professional ITIL-style support ticket."""
    prompt = f"""أنت مساعد متخصص في كتابة تذاكر الدعم الفني (Support Tickets) بصيغة ITIL احترافية.

معلومات المشكلة:
- الوصف: {description}
- نوع الجهاز: {device}
- ملخص التشخيص: {diagnosis_summary}

أنشئ تذكرة دعم احترافية تتضمن:
- Title (عنوان مختصر وواضح)
- Priority (Critical/High/Medium/Low)
- Category (نوع المشكلة)
- Description (وصف تفصيلي)
- Impact (الأثر على الأعمال)
- Steps to Reproduce (خطوات حدوث المشكلة)
- Recommended Action (الإجراء الموصى به)

اكتب التذكرة بشكل منظم وجاهز للنسخ المباشر في أي نظام Ticketing مثل ServiceNow أو Jira."""

    return ask_claude(prompt, max_tokens=900)


def generate_report(description: str, diagnosis_summary: str, device: str, log_findings: list) -> str:
    """Use Claude to generate a clear management-ready report."""
    findings_text = ", ".join(log_findings) if log_findings else "لا توجد نتائج من السجلات"
    prompt = f"""أنت محلل شبكات محترف. اكتب تقريراً تنفيذياً واضحاً جاهزاً لإرساله للمدير.

المشكلة: {description}
نوع الجهاز: {device}
التشخيص: {diagnosis_summary}
نتائج تحليل السجلات: {findings_text}

التقرير يجب أن يتضمن:
1. ملخص تنفيذي (Executive Summary) — فقرة واحدة
2. تفاصيل المشكلة الفنية
3. الأثر المحتمل على العمل
4. الإجراءات المتخذة أو الموصى بها
5. التوصيات للمستقبل لمنع تكرار المشكلة

اكتب بأسلوب احترافي مختصر باللغة العربية، مناسب لتقرير رسمي."""

    return ask_claude(prompt, max_tokens=1000)


# ─────────────────────────────────────────────
# LOG TYPE & SOURCE DETECTION
# ─────────────────────────────────────────────
LOG_TYPE_SIGNATURES = {
    "Firewall Log": ["deny", "permit", "access-list", "blocked", "drop", "firewall"],
    "Syslog (Cisco)": ["%LINK", "%SYS", "%OSPF", "%STP", "%SEC", "%LINEPROTO"],
    "Authentication Log": ["login failed", "authentication failed", "invalid user", "failed password", "sshd"],
    "IDS/IPS Alert": ["signature", "alert", "intrusion", "snort", "suricata", "threat detected"],
    "Windows Event Log": ["event id", "eventid", "logon type", "security-auditing"],
    "Linux Syslog": ["kernel:", "systemd", "sudo:", "cron", "/var/log"],
    "DHCP Log": ["dhcpack", "dhcpdiscover", "dhcprequest", "lease"],
    "VPN Log": ["vpn", "ipsec", "tunnel", "phase 1", "phase 2"],
    "Web Server Log": ["GET /", "POST /", "HTTP/1.1", "404", "500", "user-agent"],
}

LOG_SOURCE_SIGNATURES = {
    "Cisco IOS": ["%LINK", "%SYS-", "%OSPF", "show logging", "ios"],
    "Fortinet FortiGate": ["fortigate", "fortios", "devid=", "policyid="],
    "Palo Alto": ["panos", "traffic-log", "threat-log"],
    "Linux/Unix": ["kernel:", "systemd", "/var/log/", "sudo:"],
    "Windows Server": ["event id", "eventid", "winlogbeat"],
    "Mikrotik RouterOS": ["routeros", "winbox", "mikrotik"],
    "pfSense": ["pfsense", "filterlog"],
}


def detect_log_type(log_text: str) -> str:
    """Detect what kind of log this is based on content patterns."""
    log_lower = log_text.lower()
    for log_type, signatures in LOG_TYPE_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in log_lower:
                return log_type
    return "Unknown / Generic Log"


def detect_log_source(log_text: str) -> str:
    """Detect the device/system that generated this log."""
    log_lower = log_text.lower()
    for source, signatures in LOG_SOURCE_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in log_lower:
                return source
    return "Unknown Source"


def analyze_security_log(log_text: str, device: str) -> str:
    """Use Claude as a specialized Network Security Engineer to deeply
    analyze a log for threats, attacks, and anomalies."""

    log_type = detect_log_type(log_text)
    log_source = detect_log_source(log_text)

    prompt = f"""أنت مهندس أمن شبكات (Network Security Engineer) خبير متخصص في تحليل سجلات الأحداث (Log Analysis).

نوع السجل المكتشف: {log_type}
مصدر السجل المحتمل: {log_source}
نوع الجهاز المُدخل من المستخدم: {device}

محتوى السجل (Log):
{log_text}

حلل هذا السجل بعمق وقدّم:

1. **نوع السجل ومصدره** — تأكيد أو تصحيح النوع والمصدر المكتشف تلقائياً

2. **الأحداث المكتشفة** — قائمة بكل حدث مهم وجدته في السجل

3. **التهديدات الأمنية المحتملة** — إن وُجدت، حدد:
   - نوع الهجوم المحتمل (Brute Force, Port Scan, DDoS, Privilege Escalation, إلخ)
   - عناوين IP المشبوهة إن وجدت
   - مستوى الخطورة (CRITICAL/HIGH/MEDIUM/LOW/NONE)

4. **التحليل الفني** — تفسير تقني لما يحدث في الشبكة بناءً على السجل

5. **الإجراءات الموصى بها** — خطوات فورية للاستجابة، بصيغة أوامر تقنية مناسبة لجهاز {device} إن أمكن

6. **توصيات وقائية** — كيف نمنع تكرار هذا مستقبلاً

اكتب التحليل بالعربية والإنجليزية معاً، بأسلوب مهندس أمن محترف، ومنظم بعناوين واضحة."""

    return ask_claude(prompt, max_tokens=1800)


# ─────────────────────────────────────────────
# SLANG & COLLOQUIAL DICTIONARY
# عامية سعودية / خليجية / عربية شاملة
# ─────────────────────────────────────────────
SLANG_MAP = {
    # ══ بطء الشبكة ══
    "يتهنج": "slow",
    "يتعلق": "slow",
    "ثقيل": "slow",
    "بطي": "slow",
    "بطيييء": "slow",
    "يتلخبط": "slow",
    "يتأخر": "latency",
    "فيه تأخير": "latency",
    "استجابته ثقيلة": "latency",
    "ما يفتح بسرعة": "slow",
    "تقيل": "slow",
    "جامد": "slow",
    "ما يمشي": "slow",

    # ══ انقطاع الشبكة ══
    "واقف": "down",
    "نايم": "down",
    "مو شغال": "not working",
    "ما يشتغل": "not working",
    "انقطع": "disconnect",
    "ينقطع": "disconnect",
    "يتقطع": "packet loss",
    "مقطوع": "disconnect",
    "راح": "down",
    "طاح": "down",
    "انهار": "down",
    "وقع": "down",
    "ما فيه نت": "no ip",
    "النت راح": "disconnect",
    "النت طاح": "disconnect",
    "النت وقع": "disconnect",
    "الشبكة راحت": "disconnect",
    "الشبكة طاحت": "disconnect",

    # ══ عدم الوصول ══
    "ما يوصل": "unreachable",
    "ما يفتح": "cannot reach",
    "ما يكمل": "cannot reach",
    "ما يدخل": "cannot reach",
    "ما يشوف": "unreachable",
    "ما يلاقي": "unreachable",
    "محجوب": "cannot reach",
    "موقوف": "cannot reach",
    "ما يرد": "packet loss",
    "ما يجاوب": "packet loss",

    # ══ عنوان IP ══
    "ما يحصل نت": "no ip",
    "ما يحصل عنوان": "no ip",
    "ما يجي اي بي": "no ip",
    "ما حصل على ip": "no ip",
    "ما حصل عنوان": "no ip",
    "ما يستقبل": "no ip",
    "ما يتحصل": "no ip",

    # ══ الطابعة ══
    "ما تطبع": "not printing",
    "الطابعه وقفت": "printer offline",
    "الطابعه نايمة": "printer offline",
    "الطابعه مو شغالة": "printer offline",
    "الطابعه ما تشتغل": "not printing",
    "الطابعه محجوبة": "printer offline",
    "مشكلة الطابعة": "printer",
    "الطابعه ما تردنا": "not printing",

    # ══ الواي فاي ══
    "واي فاي ضعيف": "wifi signal",
    "النت الوايرلس": "wireless",
    "الوايرليس": "wireless",
    "اللاسلكي": "wireless",
    "الشبكة اللاسلكية": "wireless",
    "ينقطع الواي فاي": "wifi disconnect",
    "الواي فاي يتقطع": "wifi packet loss",
    "الواي فاي ثقيل": "wifi slow",
    "إشارة ضعيفة": "weak signal",

    # ══ التوجيه ══
    "ما يوصل للسيرفر": "cannot reach",
    "ما يوصل للراوتر": "cannot reach gateway",
    "ما يشوف الجهاز": "unreachable",
    "الروت مو صح": "routing",
    "مشكلة توجيه": "routing",

    # ══ عام ══
    "فيه مشكلة": "general",
    "مو زين": "not working",
    "خربان": "not working",
    "معطل": "not working",
    "فيه عطل": "not working",
    "فيه خلل": "not working",
    "كل شي واقف": "down",

    # ══ إنجليزي عامي ══
    "super slow": "slow",
    "not working": "unreachable",
    "keeps dropping": "packet loss",
    "cant connect": "cannot reach",
    "wont print": "not printing",
    "no internet": "no ip",
    "wifi sucks": "wifi",
    "dropping out": "disconnect",
    "freezing": "slow",
    "laggy": "latency",
    "timing out": "packet loss",
    "goes down": "disconnect",
    "keeps disconnecting": "disconnect",
}

def normalize_description(text: str) -> str:
    """Translate slang/colloquial terms to standard keywords."""
    normalized = text
    for slang, standard in SLANG_MAP.items():
        if slang in normalized.lower():
            normalized = normalized.lower().replace(slang, standard)
    return normalized


# ─────────────────────────────────────────────
# NETWORK KNOWLEDGE BASE
# ─────────────────────────────────────────────
DEVICE_COMMANDS = {
    "cisco": {
        "ping":        "ping {target}",
        "traceroute":  "traceroute {target}",
        "interfaces":  "show interfaces",
        "ip_brief":    "show ip interface brief",
        "routing":     "show ip route",
        "arp":         "show arp",
        "logs":        "show logging",
        "cpu":         "show processes cpu sorted",
        "memory":      "show processes memory sorted",
        "vlan":        "show vlan brief",
        "spanning":    "show spanning-tree",
        "neighbors":   "show cdp neighbors detail",
    },
    "mikrotik": {
        "ping":        "/tool ping {target}",
        "interfaces":  "/interface print",
        "routing":     "/ip route print",
        "arp":         "/ip arp print",
        "logs":        "/log print",
        "cpu":         "/system resource print",
    },
    "juniper": {
        "ping":        "ping {target}",
        "interfaces":  "show interfaces terse",
        "routing":     "show route",
        "arp":         "show arp",
        "logs":        "show log messages",
        "cpu":         "show chassis routing-engine",
    },
    "fortinet": {
        "ping":        "execute ping {target}",
        "interfaces":  "get system interface",
        "routing":     "get router info routing-table all",
        "logs":        "get log memory filter",
        "cpu":         "get system performance status",
    }
}

ISSUE_PATTERNS = {
    "slow": {
        "keywords": ["slow", "بطيء", "بطيئة", "latency", "delay", "تأخير", "بطء"],
        "causes": [
            "High bandwidth utilization on uplink | استهلاك عالي للباندويث",
            "Duplex mismatch on interface | عدم تطابق إعدادات Duplex",
            "Spanning tree topology change | تغيير في مخطط Spanning Tree",
            "High CPU on network device | ارتفاع استهلاك المعالج",
            "DNS resolution delays | تأخير في استجابة DNS"
        ],
        "commands": ["show interfaces", "show processes cpu sorted", "show spanning-tree", "show ip interface brief"],
        "solutions": [
            "تحقق من الاستهلاك / Check utilization: show interfaces {interface}",
            "تحقق من Duplex / Verify duplex: show interfaces {interface} | include duplex",
            "تحقق من STP / Check STP: show spanning-tree detail",
            "راقب المعالج / Monitor CPU: show processes cpu sorted | head 20"
        ]
    },
    "packet_loss": {
        "keywords": ["packet loss", "فقدان", "dropping", "يسقط", "ping fails", "لا يرد", "loss"],
        "causes": [
            "Physical layer issue (cable/SFP) | مشكلة في الكابل أو المنفذ",
            "Interface error counters increasing | ارتفاع أخطاء الواجهة",
            "QoS policy dropping packets | سياسة QoS تسقط الحزم",
            "MTU mismatch | عدم تطابق حجم MTU",
            "Routing loop | حلقة توجيه"
        ],
        "commands": ["show interfaces", "show ip route", "ping", "show ip interface brief"],
        "solutions": [
            "تحقق من الأخطاء / Check errors: show interfaces | include error",
            "تحقق من MTU / Verify MTU: show interfaces | include MTU",
            "تحقق من التوجيه / Check routing: show ip route {destination}",
            "اختبر الاتصال / Test: ping {target} repeat 100"
        ]
    },
    "vlan": {
        "keywords": ["vlan", "فلان", "trunk", "access", "tagged", "untagged", "segmentation"],
        "causes": [
            "VLAN not configured on switch | الـ VLAN غير مضاف على السويتش",
            "Trunk port not allowing VLAN | منفذ Trunk لا يسمح بالـ VLAN",
            "Native VLAN mismatch | عدم تطابق الـ Native VLAN",
            "Port in wrong VLAN | المنفذ في VLAN خاطئ",
            "SVI not configured | الـ SVI غير مضبوط"
        ],
        "commands": ["show vlan brief", "show interfaces trunk", "show spanning-tree vlan"],
        "solutions": [
            "تحقق من VLAN / Verify VLAN: show vlan brief",
            "تحقق من Trunk / Check trunk: show interfaces trunk",
            "تحقق من المنفذ / Verify port: show interfaces {interface} switchport",
            "تحقق من SVI / Check SVI: show ip interface brief | include Vlan"
        ]
    },
    "routing": {
        "keywords": ["route", "routing", "راوتينج", "لا يصل", "unreachable", "cannot reach", "gateway", "وصول"],
        "causes": [
            "Missing route in routing table | مسار مفقود في جدول التوجيه",
            "Wrong default gateway | البوابة الافتراضية خاطئة",
            "Routing protocol not converged | بروتوكول التوجيه لم يتقارب",
            "ACL blocking traffic | قائمة ACL تحجب الحركة",
            "NAT misconfiguration | إعداد NAT خاطئ"
        ],
        "commands": ["show ip route", "show ip protocols", "show access-lists"],
        "solutions": [
            "تحقق من المسار / Check route: show ip route {destination}",
            "تحقق من البوابة / Verify default: show ip route 0.0.0.0",
            "تحقق من البروتوكول / Check protocol: show ip protocols",
            "تحقق من ACL / Verify ACL: show access-lists",
            "تتبع المسار / Traceroute: traceroute {destination}"
        ]
    },
    "dhcp": {
        "keywords": ["dhcp", "ip address", "لا يحصل", "no ip", "169.254", "apipa", "عنوان"],
        "causes": [
            "DHCP server not reachable | خادم DHCP غير متاح",
            "DHCP pool exhausted | نفاد عناوين IP في الـ Pool",
            "DHCP relay not configured | الـ DHCP Relay غير مضبوط",
            "Rogue DHCP server | خادم DHCP غير مصرح",
            "IP conflict | تعارض في عناوين IP"
        ],
        "commands": ["show ip dhcp pool", "show ip dhcp binding", "show ip dhcp conflict"],
        "solutions": [
            "تحقق من الـ Pool / Check pool: show ip dhcp pool",
            "راجع التخصيصات / View bindings: show ip dhcp binding",
            "تحقق من التعارضات / Check conflicts: show ip dhcp conflict",
            "تحقق من Relay / Verify relay: show run | include helper-address"
        ]
    },
    "wifi": {
        "keywords": ["wifi", "wireless", "واي فاي", "لاسلكي", "signal", "إشارة", "disconnect", "ينقطع"],
        "causes": [
            "Weak signal / RF interference | إشارة ضعيفة أو تشويش",
            "Channel congestion | ازدحام في القناة",
            "Authentication failure | فشل المصادقة",
            "IP address conflict | تعارض في عناوين IP",
            "AP overloaded | نقطة الوصول مثقلة"
        ],
        "commands": ["show wireless client summary", "show ap summary", "show wireless statistics"],
        "solutions": [
            "تحقق من نقاط الوصول / Check AP: show ap summary",
            "راجع الأجهزة المتصلة / View clients: show wireless client summary",
            "تحقق من القناة / Check channel: show ap dot11 5ghz summary",
            "تحقق من المصادقة / Verify auth: show wireless client detail mac {mac}"
        ]
    },
    "printer": {
        "keywords": ["printer", "طابعة", "طابعه", "print", "لا تطبع", "not printing", "offline", "9100", "515", "printing"],
        "causes": [
            "Printer IP changed or unreachable | عنوان IP الطابعة تغير أو لا يمكن الوصول إليه",
            "Port 9100 or 515 blocked by firewall | المنفذ 9100 أو 515 محجوب",
            "Printer offline or powered off | الطابعة مغلقة أو في وضع offline",
            "Wrong printer IP configured on PC | IP الطابعة خاطئ على الجهاز",
            "Print spooler service stopped | خدمة الطباعة متوقفة"
        ],
        "commands": ["ping {printer_ip}", "show ip arp", "show interfaces", "show ip interface brief"],
        "solutions": [
            "اختبر الاتصال / Ping printer: ping {printer_ip}",
            "تحقق من ARP / Check ARP: show ip arp | include {printer_ip}",
            "اختبر المنفذ / Test port 9100: telnet {printer_ip} 9100",
            "تحقق من الجدار الناري / Check firewall: show access-lists",
            "تحقق من VLAN الطابعة / Check printer VLAN: show vlan brief"
        ]
    }
}


# ─────────────────────────────────────────────
# ISSUE DETECTOR
# ─────────────────────────────────────────────
def detect_issue(description: str) -> str:
    normalized = normalize_description(description)
    description_lower = normalized.lower()
    for issue_type, data in ISSUE_PATTERNS.items():
        for keyword in data["keywords"]:
            if keyword in description_lower:
                return issue_type
    return "general"


def get_local_diagnosis(issue_type: str, description: str, device: str) -> dict:
    if issue_type == "general":
        return {
            "issue_type": "General Network Issue",
            "probable_causes": ["Unknown — requires further investigation"],
            "diagnostic_commands": DEVICE_COMMANDS.get(device, {}).get("interfaces", "show interfaces"),
            "solutions": ["Gather more information about the symptoms"],
            "severity": "UNKNOWN"
        }

    data = ISSUE_PATTERNS[issue_type]
    device_cmds = DEVICE_COMMANDS.get(device, DEVICE_COMMANDS["cisco"])

    relevant_commands = []
    for cmd_key in data.get("commands", []):
        for key, cmd in device_cmds.items():
            if any(word in cmd for word in cmd_key.split()):
                relevant_commands.append(cmd)
                break

    return {
        "issue_type": issue_type.replace("_", " ").title(),
        "probable_causes": data["causes"],
        "diagnostic_commands": relevant_commands or list(device_cmds.values())[:4],
        "solutions": data["solutions"],
        "severity": "HIGH" if issue_type in ["packet_loss", "routing"] else "MEDIUM"
    }


# ─────────────────────────────────────────────
# LOG ANALYZER
# ─────────────────────────────────────────────
def analyze_log(log_text: str) -> list:
    findings = []
    patterns = {
        "Interface Down":     ["line protocol is down", "link down", "interface.*down"],
        "High CPU":           ["cpu utilization", "cpu threshold", "high cpu"],
        "Memory Warning":     ["memory warning", "low memory", "out of memory"],
        "Authentication Fail":["authentication failed", "login failed", "invalid password"],
        "STP Change":         ["topology change", "stp", "spanning-tree"],
        "DHCP Issue":         ["dhcp", "no address", "address conflict"],
        "Routing Change":     ["neighbor.*down", "adjacency", "ospf", "bgp"],
    }

    log_lower = log_text.lower()
    for finding, keywords in patterns.items():
        for kw in keywords:
            if kw in log_lower:
                findings.append(finding)
                break

    return findings if findings else ["No critical issues detected in logs"]


# ─────────────────────────────────────────────
# SAVE REPORT
# ─────────────────────────────────────────────
def save_report(data: dict, filename: str = None) -> str:
    if not filename:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"netmind_report_{ts}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n  [✓] Report saved: {filename}")
    print(f"  [✓] Open netmind.html to view results.\n")
    return filename


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n" + "="*55)
    print("  NetMind — AI-Powered Network Troubleshooter")
    print("  Built by: Ahmed Al-Ghamdi | Network Engineer")
    print("="*55)

    # Device type
    print("\n  Select device type:")
    print("  1. Cisco  2. Mikrotik  3. Juniper  4. Fortinet")
    choice = input("\n  Choice (1-4): ").strip()
    device_map = {"1": "cisco", "2": "mikrotik", "3": "juniper", "4": "fortinet"}
    device = device_map.get(choice, "cisco")
    print(f"  → Device: {device.title()}")

    # Problem description
    print("\n  Describe your network issue (Arabic or English):")
    description = input("  > ").strip()

    # Optional log
    print("\n  Paste device log (optional — press Enter to skip):")
    log_text = input("  > ").strip()

    # Local analysis (fast, offline fallback)
    issue_type = detect_issue(description)
    diagnosis = get_local_diagnosis(issue_type, description, device)

    log_findings = []
    ai_log_analysis = ""
    log_type_detected = ""
    log_source_detected = ""

    if log_text:
        log_findings = analyze_log(log_text)
        log_type_detected = detect_log_type(log_text)
        log_source_detected = detect_log_source(log_text)
        print(f"\n  [📋] Log Type   : {log_type_detected}")
        print(f"  [🔌] Log Source : {log_source_detected}")

    # ── AI-Powered Analysis via Claude ──
    use_ai = input("\n  Use Claude AI for deep analysis? (y/n): ").strip().lower()

    ai_diagnosis = ""
    ai_ticket = ""
    ai_report = ""

    if use_ai == "y":
        print("\n  [*] Asking Claude for intelligent diagnosis...")
        ai_diagnosis = generate_ai_diagnosis(description, device, log_text)
        print(f"\n{'='*55}")
        print("  🤖 AI DIAGNOSIS (Claude)")
        print(f"{'='*55}")
        print(ai_diagnosis)

        if log_text:
            gen_security = input("\n  Run deep SECURITY log analysis? (y/n): ").strip().lower()
            if gen_security == "y":
                print("\n  [*] Analyzing log as Network Security Engineer...")
                ai_log_analysis = analyze_security_log(log_text, device)
                print(f"\n{'='*55}")
                print(f"  🔐 SECURITY LOG ANALYSIS")
                print(f"  Type: {log_type_detected} | Source: {log_source_detected}")
                print(f"{'='*55}")
                print(ai_log_analysis)

        gen_ticket = input("\n  Generate support ticket? (y/n): ").strip().lower()
        if gen_ticket == "y":
            print("\n  [*] Generating ticket...")
            ai_ticket = generate_ticket(description, ai_diagnosis, device)
            print(f"\n{'='*55}")
            print("  🎫 SUPPORT TICKET")
            print(f"{'='*55}")
            print(ai_ticket)

        gen_report = input("\n  Generate management report? (y/n): ").strip().lower()
        if gen_report == "y":
            print("\n  [*] Generating report...")
            ai_report = generate_report(description, ai_diagnosis, device, log_findings)
            print(f"\n{'='*55}")
            print("  📋 MANAGEMENT REPORT")
            print(f"{'='*55}")
            print(ai_report)
    else:
        # Display local (rule-based) results
        print(f"\n{'='*55}")
        print(f"  DIAGNOSIS RESULT (Local)")
        print(f"{'='*55}")
        print(f"  Issue Type : {diagnosis['issue_type']}")
        print(f"  Severity   : {diagnosis['severity']}")
        print(f"\n  Probable Causes:")
        for cause in diagnosis['probable_causes'][:3]:
            print(f"    • {cause}")
        print(f"\n  Diagnostic Commands ({device.title()}):")
        for cmd in diagnosis['diagnostic_commands'][:4]:
            print(f"    $ {cmd}")
        print(f"\n  Recommended Solutions:")
        for sol in diagnosis['solutions'][:3]:
            print(f"    → {sol}")
        if log_findings:
            print(f"\n  Log Analysis Findings:")
            for finding in log_findings:
                print(f"    ⚠ {finding}")
        print(f"{'='*55}\n")

    # Build full report
    report = {
        "tool": "NetMind — AI-Powered Network Troubleshooter",
        "author": "Ahmed Al-Ghamdi",
        "timestamp": datetime.datetime.now().isoformat(),
        "device_type": device,
        "issue_description": description,
        "local_diagnosis": diagnosis,
        "ai_diagnosis": ai_diagnosis,
        "ai_ticket": ai_ticket,
        "ai_report": ai_report,
        "log_findings": log_findings,
        "log_type_detected": log_type_detected,
        "log_source_detected": log_source_detected,
        "ai_security_log_analysis": ai_log_analysis,
    }

    save_report(report)


if __name__ == "__main__":
    main()