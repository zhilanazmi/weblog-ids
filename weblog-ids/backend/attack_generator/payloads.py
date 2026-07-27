"""
payloads.py - Daftar payload dan request untuk skenario uji terkontrol.

Ground truth (label aktual) ditentukan dari jenis request yang dikirim:
- XSS_PAYLOADS     -> actual_label "XSS"
- SQLI_PAYLOADS    -> actual_label "SQLi"
- MULTIPLE_PAYLOADS-> actual_label "Multiple" (memicu rule XSS dan SQLi)
- NORMAL_REQUESTS  -> actual_label "Normal"

Payload dibuat selaras ruleset agar mayoritas terdeteksi (true positive),
plus beberapa variasi encoding/obfuscation untuk menguji preprocessing.
"""

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert(1)>",
    "<script>prompt('xss')</script>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<img src=x onerror=confirm(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",  # URL-encoded (uji decoding)
    "<script>alert(document.cookie)</script>",
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' UNION SELECT 1,2--",
    "1' AND 1=1--",
    "' OR 1=1#",
    "admin'--",
    "1' UNION SELECT user, password FROM users--",
    "' AND SLEEP(5)--",
    "1' UNION SELECT table_name FROM information_schema.tables--",
    "' OR (1=1)--",
    "1' SELECT @@version--",
    "1' OR 1=1 LIMIT 1--",
]

MULTIPLE_PAYLOADS = [
    "<script>alert(1)</script>' OR 1=1--",
    "1' UNION SELECT 1,2--<script>prompt(1)</script>",
    "<img src=x onerror=alert(1)>' UNION SELECT user FROM users--",
    "' OR '1'='1' <svg onload=alert(1)>",
]

NORMAL_REQUESTS = [
    "/",
    "/login.php",
    "/index.php",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/sqli/",
    "/security.php",
    "/instructions.php",
    "/setup.php",
    "/about.php",
    "/dvwa/css/main.css",
    "/dvwa/js/dvwaPage.js",
    "/favicon.ico",
]
