# Security Policy

Windows Memory Entropy Scanner is a defensive local-inspection utility. It reads memory only from a process selected by the operator and is intended for authorized debugging, lab, and incident-response work.

## Reporting

Please report security issues through the repository owner profile:

https://github.com/zhaozehan0424-design

Do not open a public issue containing process dumps, credentials, tokens, private logs, or screenshots with sensitive data.

## Sensitive Data

Never commit:

- Real memory dumps or process captures
- Extracted credentials, keys, tokens, or session data
- Private incident-response logs
- Generated binary output
- Local virtual environments or cache directories

## Responsible Use

Use the scanner only on systems and processes you own or are explicitly authorized to inspect. The included `tools/hold_hex_target.py` script is the preferred target for repeatable public tests.
