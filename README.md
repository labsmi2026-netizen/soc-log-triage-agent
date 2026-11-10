# SOC Log Triage Agent (local, no API key)

A small blue-team practice agent that triages an SSH authentication log. It runs entirely on your own computer with a local model through [Ollama](https://ollama.com), so no logs leave the machine and no API key or paid service is needed.

**Design rule: code finds the facts, the model only explains them.** Small local models are unreliable at counting and at keeping several IPs apart, so all detection is plain Python. The model sees one IP's verified findings at a time and writes a short analyst note.

## How it works

1. `parse_log` reads `Failed password` / `Accepted password` lines from `sshd`.
2. `analyze_auth_log` computes per-IP facts and raises alerts:
   - **brute-force burst**: many failures in a short window
   - **repeat activity**: failures resume after a long pause
   - **success after failure**: a login succeeds shortly after a failure from the same IP
3. `findings_by_ip` splits the findings into one block per IP.
4. `explain_ip` asks the local model (`llama3.2`, temperature 0) for a two-sentence note on that single block, using a small response playbook per alert type.
5. `build_report` prints the report: most urgent IP first, the code-computed findings, then the model's note.

## Run it

Requirements: Python 3, Ollama installed and running.

```
ollama pull llama3.2
py -m pip install ollama
py soc_agent.py sample_auth.log
```

`sample_auth.log` is a small fake log (documentation-range IPs) with one brute-force source and one suspicious login.

## Sample output

```
SOC TRIAGE REPORT: sample_auth.log
IPs with alerts: 2 of 3

IP 198.51.100.7 (EXTERNAL): 1 failed, 1 successful
  usernames tried: anwar
  failures between 10:30:44 and 10:30:44
  ALERT success after failure: user 'anwar' logged in at 10:31:02, 18s after a failure from the same IP
  ANALYST NOTE (model): This matters because the user 'anwar' successfully logged in 18 seconds after a
  previous failed attempt from the same IP address ... The single most important next step is to confirm
  with the account owner that the login was indeed theirs ...

IP 203.0.113.45 (EXTERNAL): 8 failed, 0 successful
  usernames tried: admin, root, test, ubuntu
  failures between 10:14:03 and 11:02:22
  ALERT brute-force burst: 5+ failures within 11s at 10:14:03
  ALERT repeat activity: failures resumed at 11:02:19 after a pause since 10:14:17
  ANALYST NOTE (model): This matters because the IP address has attempted to log in 8 times with different
  usernames, but none of the attempts were successful ... The single most important next step is to block
  or rate-limit the source IP address ...

No alerts:
  IP 192.168.1.20 (internal): 0 failed, 1 successful
```

## Tuning

Detection thresholds are constants at the top of `soc_agent.py`:

| Setting | Default | Meaning |
|---|---|---|
| `BRUTE_FORCE_FAILURES` | 5 | failures needed for a burst |
| `BRUTE_FORCE_WINDOW_S` | 60 | window (seconds) for those failures |
| `SUCCESS_AFTER_FAIL_S` | 300 | success this soon after a failure is flagged |
| `NEW_BURST_GAP_S` | 600 | pause (seconds) that counts as "came back" |

## Limitations

- The model's notes can contain wording that the data does not support (for example speculation about intent). Always read them against the code-computed findings above them.
- Only OpenSSH password events are parsed. Key-based logins, other services and Windows events are not covered yet.
- It reads one log file; there is no live monitoring, and nothing is blocked automatically. The agent is read-only.

## Roadmap

- Windows Security log support (event IDs 4625 failed / 4624 successful logon)
- A tool that checks source IPs against a blocklist file
- Test on larger, more varied logs and tune thresholds
