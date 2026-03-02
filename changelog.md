# EasyRecon Changelog

## v1.2
- Amended portscan.py's host discovery parsing to include http_title. 
- Fixed dirbusting module not including -H argument if host found. 
- Added smbenum.py module running crackmapexec and attempting anon/null.
- Added ldapenum.py module; attempts null connection, enumerates AD users. 

## v1.1
- Switched subdomain filtering from word-count to content-length.
- Added HTTP header probing to extract backend host indicators (e.g. 'X-Backend-Server').
- Filtered out default SSL hostnames like 'localhost.localdomain'.
- Fixed enumeration failing when HTTP service runs on non-standard ports (e.g. :5000)
- Adjusted timeout length on subdomain enumeration from 180 to 120.
- Added technology_stack module for CMS and version detection.

## v1.0 
- TCP port scanning with service detection
- Directory brute forcing for web endpoints
- Subdomain enumeration using wordlists.
