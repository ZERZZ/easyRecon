# EasyRecon Changelog

## v1.3 - Mar 9, 2026
- Added rpcenum.py module; attempts null bind and attempts enumdomusers.
- Added parsing for nmap ftp-anon NSE script to detect anon FTP access.
- Added ftpenum.py module; connects anonymously and parses interesting files. 

## v1.2 - Mar 2, 2026
- Amended portscan.py's host discovery parsing to include http_title. 
- Fixed dirbuster.py module not including -H argument if host found. 
- Added smbenum.py module running crackmapexec and attempting anon/null.
- Added ldapenum.py module; attempts null connection, enumerates AD users. 

## v1.1 - Feb 28, 2026
- Switched subdomain filtering from word-count to content-length.
- Added HTTP header probing to extract backend host indicators (e.g. 'X-Backend-Server').
- Filtered out default SSL hostnames like 'localhost.localdomain'.
- Fixed enumeration failing when HTTP service runs on non-standard ports (e.g. :5000).
- Adjusted timeout length on subdomain enumeration from 180 to 120.
- Added technology_stack module for CMS and version detection.

## v1.0 - Feb 26, 2026
- TCP port scanning with service detection.
- Directory brute forcing for web endpoints.
- Subdomain enumeration using wordlists.
