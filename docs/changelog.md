# EasyRecon Changelog

### v1.7 - April 6, 2026
- Added nfsenum.py module which attempts to access file share and mounts share to /tmp.
- Added gRPCenum.py module which attempts to enumerate methods.
- Fixed an issue with subdomain_enum.py removing numbers from IP instead of prepended subdomain. 
- Fixed issue with subdomain_enum.py missing https targets. 
- Fixed issue with legacy machines not allowing passive mode, added initial directory listing.
- Updated logic in portscan.py to cover more than the top 1000 ports. 
- Modules are now ran based on service identification first to catch services on non standard ports. 

### v1.6 - Mar 15, 2026
- Added asrep_roast.py module which runs if usernames are found from other modules. 
- Added usecreds.py module which determines where credentials can authenticate to. 
- Added a check for writable shares on SMB and a suggestion to attempt NTLM_theft.
- Added --aggressive that automatically attempts AS-REP hash cracking via hashcrack.py 
- Added null bind to rpcenum.py module, now also enumerates/filters users.
- Added user enumeration to ldapenum.py. 
- Improved parsing in portscan.py to correctly identify hostname.

### v1.5 - Mar 13, 2026
- Added RID cycling and username extraction to smbenum.py.
- Added nullbind attempt to smbenum.py if crackmapexec fails.
- Added stripping for hosts with 2+ labels for subdomain/vhost fuzzing.
- Fixed an issue with rpcenum.py incorrectly identifying enumdomusers success. 
- Fixed an issue with portscan.py incorrectly identifying web targets.
- Fixed an issue with the tool failing when no web targets were identified. 
- Fixed web modules forcing bad host from SSL cert.  
- Revamped terminal output format for readability/efficiency (utils/output.py).
- Moved banner outside of main to utils/banner.py.

### v1.4 - Mar 12, 2026
- Added gitdump.py module which dumps git locally based on http-git NSE script.
- Introduced settings.yaml for configurable tool settings.
- Updated README.md to include python / external dependencies. 
- Added wildcard detection to dirbuster.py to identify and filter wildcard responses.
- Fixed a logic error in portscan.py. 
- subdomain_enum.py renamed to vhostenum.py, new subdomain.py module created.
- Fixed HTTPS/HTTP for all web modules and centralised it in main. 
- Refactored main.py to use a dispatch dictionary. 

### v1.3 - Mar 9, 2026
- Added rpcenum.py module; attempts null bind and attempts enumdomusers.
- Added parsing for nmap ftp-anon NSE script to detect anon FTP access.
- Added ftpenum.py module; connects anonymously and parses interesting files. 

### v1.2 - Mar 2, 2026
- Amended portscan.py's host discovery parsing to include http_title. 
- Fixed dirbuster.py module not including -H argument if host found. 
- Added smbenum.py module running crackmapexec and attempting anon/null.
- Added ldapenum.py module; attempts null connection, enumerates AD users. 

### v1.1 - Feb 28, 2026
- Switched subdomain filtering from word-count to content-length.
- Added HTTP header probing to extract backend host indicators (e.g. 'X-Backend-Server').
- Filtered out default SSL hostnames like 'localhost.localdomain'.
- Fixed enumeration failing when HTTP service runs on non-standard ports (e.g. :5000).
- Adjusted timeout length on subdomain enumeration from 180 to 120.
- Added technology_stack module for CMS and version detection.

### v1.0 - Feb 26, 2026
- TCP port scanning with service detection.
- Directory brute forcing for web endpoints.
- Subdomain enumeration using wordlists.
