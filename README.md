# EasyRecon

**EasyRecon** is a web reconnaissance & enumeration tool for security testing.  
It automates common recon steps into a structured workflow.

---

## Features

- TCP port scanning with service detection  
- SSL certificate hostname extraction  
- Technology stack detection (Apache, Nginx, PHP, WordPress, etc.)  
- HTTP header analysis  
- Subdomain enumeration using host header wordlists  
- Directory brute-forcing for detected web services  
- Module-specific execution with `-o`  

---

## Usage

```bash
python3 main.py <target> [-o all|portscan|dirbuster|subdomain|techstack] [-v]
