# EasyRecon

**EasyRecon** is a reconnaissance & enumeration tool for security testing.  
It automates common recon steps across web services and AD environments.

---

## Features

Web Enumeration
- TCP port scanning with service detection  
- SSL certificate hostname extraction  
- Technology stack detection (Apache, Nginx, PHP, WordPress, etc.)  
- HTTP header analysis  
- Subdomain enumeration using host header wordlists  
- Directory brute-forcing for detected web services  

Active Directory Enumeration
- SMB anonymous bind attempt and mapping.
- LDAP anonymous bind attempt and AD users enumeration.

---

## Usage

```bash
python3 main.py <target> [-o all|portscan|dirbuster|subdomain|techstack|subenum|ldapenum] [-v]

---

## Example

```bash
python3 main.py 10.10.10.10 -o subenum -v
