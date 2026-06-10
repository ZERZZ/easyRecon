
# This module provides helper functions to add findings to the report in a consistent way.
# should be moved into report.py really but for now its ok 

from utils import report


def add_discovery(title, details=None, source=None):
    """Add a discovery finding (new service, user, share, etc.)."""
    return report.add_finding(source or "unknown", "discoveries", title, details)


def add_vulnerability(title, details=None, source=None):
    """Add a vulnerability finding."""
    return report.add_finding(source or "unknown", "vulnerabilities", title, details)


def add_misconfiguration(title, details=None, source=None):
    """Add a misconfiguration finding (null session, writable share, etc.)."""
    return report.add_finding(source or "unknown", "misconfigurations", title, details)


def add_credential(title, details=None, source=None):
    """Add a credential finding (hash, password, etc.)."""
    return report.add_finding(source or "unknown", "credentials", title, details)


def add_error(title, details=None, source=None):
    """Add an error finding (tool failure, access denied, etc.)."""
    return report.add_finding(source or "unknown", "errors", title, details)


def add_note(title, details=None, source=None):
    """Add a note finding (contextual information)."""
    return report.add_finding(source or "unknown", "notes", title, details)

