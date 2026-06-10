# EasyRecon Changelog

### v2.0 - June 10, 2026

#### Added
- Added certipy.py; uses certipy-ad to extract and parse vulnerable certificates in AD environments. 
- Added dns_enum.py which enumerates domains/subdomains using dig.
- Added a suggestion to attempt password spraying of same user, same pass if users discovered. 
- Added an additional check to portscan.py to prevent invalid domains being passed to other modules.
- Added additional 'interesting rights' to bloodhound.py.
- Added multi-list support for dirbuster.py; now by default also checks web-content/common.
- Added a --dev mode which reads directly from previous scan.xml to make development more efficient. 
- Added a high value file scan check to gitdump.py.
- Added output directory with optional setting to choose location.

#### Improved
- Updated testcreds.py to include testing for SSH. 
- Updated portscan.py http detection logic to be more robust and not miss non-standard port http services.
- Updated ldapenum.py to use credentials for enumeration if provided.
- Updated ldapenum.py to check and extract 'info' and 'description' fields for interesting artifacts.
- Updated testcreds.py to run a test command for WinRM to verify authentication and reduce false positives. 
- Updated bloodhound.py to link and create attack chains from misconfigured ACLs.
- Updated dirbuster.py parsing logic to extract only extremely valuable endpoints.
- Updated ftpenum.py to test for write access, added additional interesting files.
- Updated grpcenum.py to actually enumerate services and methods.

#### Fixed
- Fixed an issue in portscan.py where incorrect parsing of RustScan output meant ports were missed.
- Fixed certipy.py parser crash caused by inconsistent template JSON structure. 
- Disabled cve_lookup.py as it currently just produces noise. Needs refinement.
- Fixed mssql_enum.py RID cycling user parsing & enumeration.
- Fixed as-rep module hanging on non-AD environments, introduced a timeout.
- Retired legacy append_unique & recon_data.

#### Refactored
- Migrated core recon state to structured recon.json output for improved post scan analysis.
- Improved findings system, reducing noise and identifying actionable findings.


### v1.9 - May 16, 2026
- Added bloodhound.py which collects and analyses AD data.
- Added mssql_enum.py which performs RID cycling / basic enumeration.
- Updated settings.yaml to include wordlists and AI analysis customisability.
- Updated testcreds.py to include testing for ms-sql.
- Updated smbenum.py to use credentials to authenticate and enumeration if provided in --test-creds.
- Integrated optional RustScan usage for initial port discovery, significantly increasing efficiency. 
- Fixed vhostenum.py false negative; now correctly identifies vhost length.  

### v1.8 - May 4, 2026
- Added cve_lookup.py module, which looks up CVEs/exploits on nvd.nist/ExploitDB (needs refining drastically).
- Updated technology_stack.py to include data collected by Wappalyzer. 
- Fixed BlockingIOError crash in output.py when printing large outputs. 
- Updated smbenum.py with tighter criteria for successful null bind confirmation. 
- Added a .json output with key information gathered.
- Updated all modules with better success criteria for initial connection/enumeration/errors.
- Added experimental AI analysis and recommendations based on json key info.  

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
