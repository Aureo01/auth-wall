# auth-wall

A lightweight recon tool to **detect authentication walls and access control weirdness** across endpoints.

It compares responses:
- with auth
- without auth
- with fake auth  

…and tells you what’s actually protected, what isn’t, and what behaves strangely 👀

---

## Why this exists

Because access control bugs love to hide in plain sight.

Manually checking:
- authenticated vs unauthenticated responses  
- status codes  
- content differences  

is slow and error-prone.

This tool automates that first pass so you can:
- spot public endpoints fast
- identify auth walls
- catch inconsistent or broken behavior

---

## What it does

For each URL, it sends **three requests**:

1. Normal request (baseline)
2. Request with **fake Authorization + Cookie**
3. Request **without any auth headers**

Then it compares:
- HTTP status
- response length
- content type
- response body hash

Based on that, it classifies endpoints.

---

## Findings detected

### 🟢 Requires authentication
Endpoint behaves the same normally and with auth,  
but **changes when auth is removed**.

Good auth wall. Probably safe.

---

### 🔵 Does not require authentication
Endpoint behaves the same **with and without auth**,  
but **changes when auth is added**.

🚨 Public endpoint. Very interesting.

---

### 🟡 Unusual behavior without auth
Endpoint throws `500 / 502 / 503` when auth is missing.

Often a sign of:
- broken access control
- bad error handling
- logic flaws

---

## Usage

Basic run:

```bash
python3 auth_wall_detector.py -w urls.txt
Set concurrency:

bash
Copy code
python3 auth_wall_detector.py -w urls.txt -c 20
Custom output directory:

bash
Copy code
python3 auth_wall_detector.py -w urls.txt --output-dir results/

Output
Terminal

Clean table with:

finding type

severity

short explanation

URL

Files

Saved under the output directory:

findings.json

info_findings.txt

medium_findings.txt

high_findings.txt
