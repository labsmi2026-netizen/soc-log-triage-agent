"""SOC log agent (local Ollama). Python finds the facts; the model only explains them.

Needs: Ollama running, model pulled (ollama pull llama3.2), and: py -m pip install ollama
Run from the folder that holds this file and the log:
    py soc_agent.py sample_auth.log
"""
import ipaddress
import re
import sys
from collections import defaultdict
from datetime import datetime

import ollama

MODEL = "llama3.2"

# ---- Detection settings (change these to tune the alerts) ----
BRUTE_FORCE_FAILURES = 5     # this many failures ...
BRUTE_FORCE_WINDOW_S = 60    # ... inside this many seconds = brute force burst
SUCCESS_AFTER_FAIL_S = 300   # success this soon after a failure from the same IP is flagged
NEW_BURST_GAP_S = 600        # a pause longer than this means the attacker came back

INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

LINE_RE = re.compile(
    r"^(\w{3}\s+\d+\s+[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+(Failed|Accepted) password for "
    r"(?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def is_internal(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in INTERNAL_NETS)


def parse_log(path):
    """Return a list of events: (time, result, user, ip). Skips lines it does not understand."""
    events = []
    year = datetime.now().year  # syslog lines have no year
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = LINE_RE.match(line)
            if m:
                when = datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
                events.append((when, m.group(2), m.group(3), m.group(4)))
    return events


# ---------- Tools (the model may call these) ----------
def analyze_auth_log(path: str) -> str:
    """Analyze an SSH auth log and return verified findings per source IP: failure counts,
    usernames tried, brute-force bursts, repeat attacks, and successful logins that follow failures.

    Args:
        path: Path to the auth log file.
    """
    events = parse_log(path)
    if not events:
        return "No SSH password events found in this file."

    by_ip = defaultdict(list)
    for e in events:
        by_ip[e[3]].append(e)

    out = [f"Parsed {len(events)} SSH password events from {len(by_ip)} source IPs."]
    for ip, evs in sorted(by_ip.items()):
        fails = [e for e in evs if e[1] == "Failed"]
        wins = [e for e in evs if e[1] == "Accepted"]
        where = "internal" if is_internal(ip) else "EXTERNAL"
        out.append(f"\nIP {ip} ({where}): {len(fails)} failed, {len(wins)} successful")
        if fails:
            users = sorted({e[2] for e in fails})
            out.append(f"  usernames tried: {', '.join(users)}")
            out.append(f"  failures between {fails[0][0]:%H:%M:%S} and {fails[-1][0]:%H:%M:%S}")

        # brute-force burst: N failures inside the window
        times = [e[0] for e in fails]
        for i in range(len(times) - BRUTE_FORCE_FAILURES + 1):
            span = (times[i + BRUTE_FORCE_FAILURES - 1] - times[i]).total_seconds()
            if span <= BRUTE_FORCE_WINDOW_S:
                out.append(f"  ALERT brute-force burst: {BRUTE_FORCE_FAILURES}+ failures within {int(span)}s at {times[i]:%H:%M:%S}")
                break

        # attacker came back after a long pause
        for a, b in zip(times, times[1:]):
            if (b - a).total_seconds() > NEW_BURST_GAP_S:
                out.append(f"  ALERT repeat activity: failures resumed at {b:%H:%M:%S} after a pause since {a:%H:%M:%S}")
                break

        # success shortly after failures from the same IP
        for w in wins:
            prior = [f for f in fails if 0 <= (w[0] - f[0]).total_seconds() <= SUCCESS_AFTER_FAIL_S]
            if prior:
                out.append(f"  ALERT success after failure: user '{w[2]}' logged in at {w[0]:%H:%M:%S}, "
                           f"{int((w[0] - prior[-1][0]).total_seconds())}s after a failure from the same IP")
    return "\n".join(out)


def get_evidence(path: str, ip: str) -> str:
    """Return the raw log lines that mention one IP address, so findings can be quoted.

    Args:
        path: Path to the auth log file.
        ip: The IP address to look up.
    """
    with open(path, "r", errors="ignore") as f:
        lines = [ln.rstrip() for ln in f if ip in ln]
    return "\n".join(lines[:30]) or f"No lines mention {ip}."


def findings_by_ip(path):
    """Split the code-computed findings into one text block per IP."""
    text = analyze_auth_log(path)
    blocks = re.split(r"\n(?=IP )", text)[1:]   # first piece is the "Parsed ..." line
    return [b.strip() for b in blocks]


IP_PROMPT = (
    "You are a SOC analyst. Below are verified findings for ONE IP address. "
    "Write exactly 2 sentences. Sentence 1: why this matters, in plain words. Do NOT repeat counts, "
    "times or lists of usernames, because they are already shown above your note. "
    "Sentence 2: the single most important next step. "
    "Use ONLY facts in the findings. Do not mention any other IP address. "
    "Pick the next step from this playbook, matching the ALERT type: "
    "'success after failure' -> confirm with the account owner that the login was theirs, "
    "check where the source IP connects from, and reset that account's password if it was not them; "
    "'brute-force burst' -> block or rate-limit the source IP and check that none of its attempts succeeded; "
    "'repeat activity' -> check whether the source IP is already blocked and add it to the blocklist."
)


def explain_ip(block):
    """Ask the model about ONE IP's findings only."""
    response = ollama.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": IP_PROMPT},
            {"role": "user", "content": block},
        ],
        options={"temperature": 0},  # same input -> same answer on every run
    )
    return response.message.content


TOOL_FUNCS = {"analyze_auth_log": analyze_auth_log, "get_evidence": get_evidence}

SYSTEM = (
    "You are a SOC triage assistant. Step 1: call analyze_auth_log on the file. "
    "Step 2: for every IP that has an ALERT, call get_evidence for that IP. "
    "Step 3: write a short report with these parts: Summary, Suspicious IPs (each with its alerts and "
    "1-2 quoted log lines as evidence), Recommended next steps. "
    "Use ONLY facts from the tool outputs. Copy numbers and usernames exactly. "
    "Never invent attempts, usernames or IPs. If something is unclear, say so."
)


# ---------- The agent loop ----------
def run_agent(task: str, path: str) -> str:
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
    for _ in range(12):  # safety cap
        response = ollama.chat(model=MODEL, messages=messages, tools=list(TOOL_FUNCS.values()))
        messages.append(response.message)
        if not response.message.tool_calls:
            return response.message.content
        for call in response.message.tool_calls:
            name, args = call.function.name, call.function.arguments
            print(f"[tool] {name}({args})")
            func = TOOL_FUNCS.get(name)
            try:
                out = func(**args) if func else f"unknown tool: {name}"
            except Exception as e:
                out = f"error: {e}"
            messages.append({"role": "tool", "tool_name": name, "content": str(out)})
    return "Stopped: too many steps."


def build_report(path):
    """Python builds the report; the model only writes a short note for each flagged IP."""
    blocks = findings_by_ip(path)
    flagged = [b for b in blocks if "ALERT" in b]
    quiet = [b.splitlines()[0] for b in blocks if "ALERT" not in b]
    # Most urgent first: a success after failure (possible compromise), then by number of alerts.
    flagged.sort(key=lambda b: ("success after failure" in b, b.count("ALERT")), reverse=True)

    lines = [f"SOC TRIAGE REPORT: {path}", f"IPs with alerts: {len(flagged)} of {len(blocks)}", ""]
    for b in flagged:
        print(f"[model] writing note for: {b.splitlines()[0]}")
        note = explain_ip(b).strip().replace("\n", " ")
        lines += [b, "  ANALYST NOTE (model): " + note, ""]
    if quiet:
        lines.append("No alerts:")
        lines += ["  " + q for q in quiet]
    return "\n".join(lines)


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    print("\n" + build_report(log_path))
