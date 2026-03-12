# EasyRecon

**EasyRecon** is a reconnaissance & enumeration tool for security testing.  
It automates common recon steps across web services and AD environments.  

---

# Requirements
EasyRecon relies on several external tools.

### Python Libraries
- Python 3.10+

Install required libraries:
```bash
pip install -r requirements.txt
```

### External Tools
Some modules rely on external utilities. 
```bash
nmap
feroxbuster
ffuf
curl
python3
python3-pip
pipx
git
git-dumper
```

---

# Features

### Web Enumeration
- TCP port scanning with service detection  
- SSL certificate hostname extraction  
- Technology stack detection (Apache, Nginx, PHP, WordPress, etc.)  
- HTTP header analysis  
- Subdomain enumeration using host header wordlists  
- vhost fuzz
- Directory brute-forcing with feroxbuster  
- /.git endpoint dumping and parsing of interesting data 

### Active Directory Enumeration
- SMB anonymous bind attempt and mapping  
- LDAP anonymous bind attempt and AD users enumeration  
- RPC anonymous connection attempt and enumdomusers enumeration  
- FTP anonymous connection attempt and interesting file parsing  

---

# Usage

```bash
python3 main.py <target> [-o all|portscan|dirbuster|vhostenum|subdomains|techstack|smbenum|ldapenum|rpcenum|ftpenum] [-v]
```

---

# Example

```bash
python3 main.py 10.10.10.10 -o smbenum -v
```