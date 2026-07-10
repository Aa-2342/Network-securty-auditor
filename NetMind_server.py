"""
NetMind Server — Local bridge between netmind.html dashboard and Claude API
Author: Ahmed Al-Ghamdi
Description: Runs a local server so the dashboard can talk to Claude
             without exposing the API key in the browser.
Security: protected by an access-key header, restricted CORS origins,
          and basic per-IP rate limiting.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import urllib.request
import urllib.error
import json
import os
import time
from collections import defaultdict, deque

app = Flask(__name__)

# ─────────────────────────────────────────────
# CORS — بس المصادر المسموح لها تتصل بالسيرفر
# عدّل القائمة إذا غيّرت رابط GitHub Pages أو أضفت دومين
# ─────────────────────────────────────────────
ALLOWED_ORIGINS = [
    "https://aa-2342.github.io",
    "http://localhost:5500",   # تطوير محلي (Live Server وغيره)
    "http://127.0.0.1:5500",
]
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=False)

# ─────────────────────────────────────────────
# مفتاح الوصول (Shared Secret) — لازم يطابق المفتاح
# المخزّن بإعدادات ⚙️ داخل netmind.html
# ضعه في Railway → Variables باسم NETMIND_ACCESS_KEY
# ─────────────────────────────────────────────
NETMIND_ACCESS_KEY = os.environ.get("NETMIND_ACCESS_KEY", "")

# ─────────────────────────────────────────────
# Rate Limiting بسيط: عدد طلبات محدود لكل IP
# ─────────────────────────────────────────────
RATE_LIMIT_MAX_REQUESTS = 20      # عدد الطلبات
RATE_LIMIT_WINDOW_SECONDS = 3600  # خلال ساعة وحدة
_request_log = defaultdict(deque)


def get_client_ip():
    # Railway/proxies تحط الـ IP الحقيقي بهذا الهيدر
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    q = _request_log[ip]
    while q and now - q[0] > RATE_LIMIT_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    q.append(now)
    return False


@app.before_request
def protect_routes():
    # يسمح بالطلبات التمهيدية (preflight) بدون فحص
    if request.method == "OPTIONS":
        return None
    # ما يفحص المسارات اللي مو AI endpoints (لو أضفت health check مثلاً)
    if request.path not in ("/diagnose", "/ticket", "/report", "/security-log"):
        return None

    if not NETMIND_ACCESS_KEY:
        return jsonify({"error": "السيرفر ما ضبط له مفتاح وصول (NETMIND_ACCESS_KEY) بعد."}), 503

    provided_key = request.headers.get("X-NetMind-Key", "")
    if provided_key != NETMIND_ACCESS_KEY:
        return jsonify({"error": "مفتاح الوصول غير صحيح أو مفقود."}), 401

    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({"error": "تجاوزت الحد المسموح من الطلبات. حاول لاحقاً."}), 429

    return None


# ─────────────────────────────────────────────
# المفتاح يأتي من Railway Environment Variables
# على جهازك المحلي: ضع مفتاحك هنا مباشرة
# ─────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "ضع_مفتاحك_هنا")
CLAUDE_MODEL = "claude-sonnet-4-6"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"


def ask_claude(prompt: str, max_tokens: int = 1200) -> str:
    if not ANTHROPIC_API_KEY or ANTHROPIC_API_KEY == "ضع_مفتاحك_هنا":
        return "⚠️ لم يتم إعداد مفتاح API في netmind_server.py"

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
        return f"⚠️ خطأ Claude API: {e.code} — {e.read().decode()}"
    except Exception as e:
        return f"⚠️ خطأ غير متوقع: {str(e)}"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "protected": bool(NETMIND_ACCESS_KEY)})


@app.route("/diagnose", methods=["POST"])
def diagnose():
    data = request.json
    description = data.get("description", "")
    device = data.get("device", "cisco")
    log_text = data.get("log", "")

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

اكتب الإجابة بالعربية والإنجليزية معاً، بشكل واضح ومنظم، استخدم تنسيق Markdown مع عناوين."""

    result = ask_claude(prompt, max_tokens=1200)
    return jsonify({"response": result})


@app.route("/ticket", methods=["POST"])
def ticket():
    data = request.json
    description = data.get("description", "")
    diagnosis_summary = data.get("diagnosis", "")
    device = data.get("device", "cisco")

    prompt = f"""أنت مساعد متخصص في كتابة تذاكر الدعم الفني بصيغة ITIL احترافية.

معلومات المشكلة:
- الوصف: {description}
- نوع الجهاز: {device}
- ملخص التشخيص: {diagnosis_summary}

أنشئ تذكرة دعم احترافية تتضمن:
- Title
- Priority (Critical/High/Medium/Low)
- Category
- Description
- Impact
- Steps to Reproduce
- Recommended Action

اكتب التذكرة بشكل منظم وجاهز للنسخ المباشر، استخدم تنسيق Markdown."""

    result = ask_claude(prompt, max_tokens=900)
    return jsonify({"response": result})


@app.route("/report", methods=["POST"])
def report():
    data = request.json
    description = data.get("description", "")
    diagnosis_summary = data.get("diagnosis", "")
    device = data.get("device", "cisco")
    log_findings = data.get("logFindings", [])

    findings_text = ", ".join(log_findings) if log_findings else "لا توجد نتائج من السجلات"
    prompt = f"""أنت محلل شبكات محترف. اكتب تقريراً تنفيذياً واضحاً جاهزاً لإرساله للمدير.

المشكلة: {description}
نوع الجهاز: {device}
التشخيص: {diagnosis_summary}
نتائج تحليل السجلات: {findings_text}

التقرير يجب أن يتضمن:
1. ملخص تنفيذي (فقرة واحدة)
2. تفاصيل المشكلة الفنية
3. الأثر المحتمل على العمل
4. الإجراءات الموصى بها
5. توصيات لمنع التكرار

اكتب بأسلوب احترافي مختصر باللغة العربية مع تنسيق Markdown."""

    result = ask_claude(prompt, max_tokens=1000)
    return jsonify({"response": result})


@app.route("/security-log", methods=["POST"])
def security_log():
    data = request.json
    log_text = data.get("log", "")
    device = data.get("device", "cisco")

    prompt = f"""أنت مهندس أمن شبكات خبير متخصص في تحليل سجلات الأحداث.

نوع الجهاز: {device}
محتوى السجل:
{log_text}

حلل هذا السجل وقدّم:
1. نوع السجل ومصدره
2. الأحداث المكتشفة
3. التهديدات الأمنية المحتملة (مع IPs مشبوهة إن وجدت ومستوى الخطورة)
4. التحليل الفني
5. الإجراءات الموصى بها
6. توصيات وقائية

اكتب بالعربية والإنجليزية معاً بأسلوب مهندس أمن محترف مع تنسيق Markdown."""

    result = ask_claude(prompt, max_tokens=1800)
    return jsonify({"response": result})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*55)
    print(f"  NetMind Server — Running on port {port}")
    print("  Keep this window open while using netmind.html")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False)
