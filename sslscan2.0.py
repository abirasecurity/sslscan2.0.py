#!/usr/bin/env python3
import subprocess
import re
import os
import sys
import argparse
import concurrent.futures
import tempfile
import threading
import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Add a lock for synchronized console output
print_lock = threading.Lock()

# Default port for scanning
DEFAULT_PORT = 443

# RC4 cipher suites associated with Bar Mitzvah vulnerability
RC4_CIPHERS = [
    "RC4-SHA", "RC4-MD5", "ECDHE-RSA-RC4-SHA", "ECDHE-ECDSA-RC4-SHA",
    "ECDH-RSA-RC4-SHA", "ECDH-ECDSA-RC4-SHA", "RSA-RC4-128-SHA",
    "RSA-RC4-128-MD5", "EXP-RC4-MD5"
]

# 3DES cipher suites associated with SWEET32 vulnerability
SWEET32_CIPHERS = [
    "DES-CBC3-SHA", "EDH-RSA-DES-CBC3-SHA", "EDH-DSS-DES-CBC3-SHA",
    "ECDHE-RSA-3DES-EDE-CBC-SHA", "ECDHE-ECDSA-3DES-EDE-CBC-SHA",
    "DH-RSA-3DES-EDE-CBC-SHA", "DH-DSS-3DES-EDE-CBC-SHA",
    "ECDH-RSA-3DES-EDE-CBC-SHA", "ECDH-ECDSA-3DES-EDE-CBC-SHA",
    "RSA-3DES-EDE-CBC-SHA"
]

# Define weak signature algorithms to check
WEAK_ALGORITHMS = [
    "md5WithRSAEncryption",
    "sha1WithRSAEncryption"
]

def parse_target_line(line):
    """Parse a line from the input file into IP and port"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if ':' in line:
        ip, port = line.split(':')
        return ip.strip(), int(port.strip())
    else:
        return line.strip(), DEFAULT_PORT

def load_targets(filename):
    """Load targets from a file"""
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                parsed = parse_target_line(line)
                if parsed:
                    targets.append(parsed)
        return targets
    except FileNotFoundError:
        with print_lock:
            print(f"{Fore.RED}Error: Input file '{filename}' not found{Style.RESET_ALL}")
        return []

def run_sslscan(ip, port):
    """Run sslscan on the target and return the output"""
    try:
        result = subprocess.run(
            ["sslscan", "--no-colour", f"{ip}:{port}"],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"ERROR: Scan timed out for {ip}:{port}"
    except Exception as e:
        return f"ERROR: Failed to scan {ip}:{port}: {str(e)}"

def parse_sslscan_output(output):
    """Parse sslscan output to extract protocol-specific cipher suites"""
    # Extract all accepted cipher suites with their protocols
    all_ciphers = []
    protocol_ciphers = {}

    # Pattern to match protocol and cipher information
    # Example: "Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384"
    cipher_pattern = r"Accepted\s+(SSLv[23]|TLSv1(?:\.[0-3])?)\s+(\d+)\s+bits\s+(\S+)"

    for match in re.finditer(cipher_pattern, output):
        protocol, bits, cipher = match.groups()

        cipher_info = {
            "protocol": protocol,
            "name": cipher,
            "bits": bits
        }

        all_ciphers.append(cipher_info)

        if protocol not in protocol_ciphers:
            protocol_ciphers[protocol] = []

        protocol_ciphers[protocol].append(cipher_info)

    # Extract signature algorithm
    sig_algo_match = re.search(r"Signature Algorithm:\s+(.+?)$", output, re.MULTILINE)
    signature_algorithm = sig_algo_match.group(1).strip() if sig_algo_match else None

    # Check for TLS versions
    tls10_enabled = "TLSv1.0   enabled" in output
    tls11_enabled = "TLSv1.1   enabled" in output

    # Extract RC4 and SWEET32 vulnerable ciphers by protocol
    rc4_vulnerable_by_protocol = {}
    sweet32_vulnerable_by_protocol = {}

    for protocol, ciphers in protocol_ciphers.items():
        for cipher_info in ciphers:
            # Check for RC4 vulnerability
            if any(rc4_cipher in cipher_info["name"] for rc4_cipher in RC4_CIPHERS):
                if protocol not in rc4_vulnerable_by_protocol:
                    rc4_vulnerable_by_protocol[protocol] = []
                rc4_vulnerable_by_protocol[protocol].append(cipher_info)

            # Check for SWEET32 vulnerability
            if any(sweet32_cipher in cipher_info["name"] for sweet32_cipher in SWEET32_CIPHERS):
                if protocol not in sweet32_vulnerable_by_protocol:
                    sweet32_vulnerable_by_protocol[protocol] = []
                sweet32_vulnerable_by_protocol[protocol].append(cipher_info)
                
    # Check for self-signed certificate
    cert_section = re.search(r'SSL Certificate:(.*?)(?:\n\n|\Z)', output, re.DOTALL)

    subject = None
    issuer = None
    self_signed = False

    if cert_section:
        cert_info = cert_section.group(1)

        # Extract Subject and Issuer
        subject_match = re.search(r'Subject:\s*(.*?)(?:\n|$)', cert_info)
        issuer_match = re.search(r'Issuer:\s*(.*?)(?:\n|$)', cert_info)

        if subject_match and issuer_match:
            subject = subject_match.group(1).strip()
            issuer = issuer_match.group(1).strip()

            # Compare Subject and Issuer
            self_signed = (subject == issuer)
    
     # Extract certificate expiration date
    expiration_match = re.search(r"Not valid after:\s+(.+?)$", output, re.MULTILINE)
    expiration_date_str = expiration_match.group(1).strip() if expiration_match else None

    expiration_date = None
    is_expired = False
    days_remaining = None

    if expiration_date_str:
        try:
            # Try to parse the date (format: May 30 12:00:00 2025 GMT)
            expiration_date = datetime.datetime.strptime(expiration_date_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            # Try alternative format if the first one fails
            try:
                expiration_date = datetime.datetime.strptime(expiration_date_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                expiration_date = None

        if expiration_date:
            # Get current date
            current_date = datetime.datetime.now()

            # Compare dates
            is_expired = expiration_date < current_date
            days_remaining = (expiration_date - current_date).days if not is_expired else 0

    return {
        "all_ciphers": all_ciphers,
        "protocol_ciphers": protocol_ciphers,
        "rc4_vulnerable_by_protocol": rc4_vulnerable_by_protocol,
        "sweet32_vulnerable_by_protocol": sweet32_vulnerable_by_protocol,
        "signature_algorithm": signature_algorithm,
        "tls10_enabled": tls10_enabled,
        "tls11_enabled": tls11_enabled,
        "self_signed": self_signed,
        "subject": subject,
        "issuer": issuer,
        "expiration_date_str": expiration_date_str,
        "expiration_date": expiration_date,
        "is_expired": is_expired,
        "days_remaining": days_remaining
    }

def scan_target(ip, port, scan_types):
    """Scan a target for all specified vulnerabilities"""
    target = f"{ip}:{port}"

    with print_lock:
        print(f"{Fore.CYAN}[+] Scanning {target}...")

    try:
        # Run sslscan once and parse the output for all checks
        output = run_sslscan(ip, port)

        if output.startswith("ERROR:"):
            with print_lock:
                print(f"{Fore.YELLOW}[!] {output}")
            return {
                "target": target,
                "error": output,
                "scan_types": scan_types
            }

        # Parse the output
        parsed_data = parse_sslscan_output(output)

        # Prepare results
        result = {
            "target": target,
            "scan_types": scan_types,
            "all_ciphers": parsed_data["all_ciphers"],
            "protocol_ciphers": parsed_data["protocol_ciphers"],
        }

        # Check for Bar Mitzvah vulnerability (RC4)
        if "bar_mitzvah" in scan_types:
            result["bar_mitzvah_vulnerable"] = bool(parsed_data["rc4_vulnerable_by_protocol"])
            result["rc4_vulnerable_by_protocol"] = parsed_data["rc4_vulnerable_by_protocol"]

        # Check for SWEET32 vulnerability (3DES)
        if "sweet32" in scan_types:
            result["sweet32_vulnerable"] = bool(parsed_data["sweet32_vulnerable_by_protocol"])
            result["sweet32_vulnerable_by_protocol"] = parsed_data["sweet32_vulnerable_by_protocol"]

        # Check for weak signature algorithms
        if "weak_signature" in scan_types:
            sig_algo = parsed_data["signature_algorithm"]
            result["signature_algorithm"] = sig_algo
            result["weak_signature_vulnerable"] = sig_algo in WEAK_ALGORITHMS if sig_algo else False

        # Check for TLSv1.0 support
        if "tls10" in scan_types:
            result["tls10_enabled"] = parsed_data["tls10_enabled"]

        # Check for TLSv1.1 support
        if "tls11" in scan_types:
            result["tls11_enabled"] = parsed_data["tls11_enabled"]
        
        # Check for self-signed certificate
        if "self_signed" in scan_types:
            result["self_signed"] = parsed_data["self_signed"]
            result["subject"] = parsed_data["subject"]
            result["issuer"] = parsed_data["issuer"]
            
        # Check for expired certificate
        if "expired_cert" in scan_types:
            result["is_expired"] = parsed_data["is_expired"]
            result["expiration_date_str"] = parsed_data["expiration_date_str"]
            result["days_remaining"] = parsed_data["days_remaining"]

        return result

    except Exception as e:
        with print_lock:
            print(f"{Fore.RED}[!] Error scanning {target}: {str(e)}")
        return {
            "target": target,
            "error": str(e),
            "scan_types": scan_types
        }

def print_scan_results(results, show_all_ciphers=False, remediation_mode=False):
    """Print scan results in a consistent format"""
    # Group results by scan type
    bar_mitzvah_results = []
    sweet32_results = []
    weak_signature_results = []
    tls10_results = []
    tls11_results = []
    self_signed_results = []
    expired_cert_results = []

    # Count statistics
    total_targets = len(results)
    error_count = 0

    for result in results:
        if "error" in result:
            error_count += 1
            continue

        target = result["target"]
        scan_types = result["scan_types"]

        if "bar_mitzvah" in scan_types:
            bar_mitzvah_results.append((target, result.get("bar_mitzvah_vulnerable", False), result))

        if "sweet32" in scan_types:
            sweet32_results.append((target, result.get("sweet32_vulnerable", False), result))

        if "weak_signature" in scan_types:
            weak_signature_results.append((target, result.get("weak_signature_vulnerable", False), result))

        if "tls10" in scan_types:
            tls10_results.append((target, result.get("tls10_enabled", False), result))

        if "tls11" in scan_types:
            tls11_results.append((target, result.get("tls11_enabled", False), result))
        
        if "self_signed" in scan_types:  # Add this block
            self_signed_results.append((target, result.get("self_signed", False), result))
            
        if "expired_cert" in scan_types:
            expired_cert_results.append((target, result.get("is_expired", False), result))

    # Print results for each scan type
    if bar_mitzvah_results:
        print_vulnerability_results("Bar Mitzvah (RC4)", bar_mitzvah_results, show_all_ciphers, remediation_mode)

    if sweet32_results:
        print_vulnerability_results("SWEET32 (3DES)", sweet32_results, show_all_ciphers, remediation_mode)

    if weak_signature_results:
        print_signature_results(weak_signature_results, remediation_mode)

    if tls10_results:
        print_tls_results("TLSv1.0", tls10_results, remediation_mode)

    if tls11_results:
        print_tls_results("TLSv1.1", tls11_results, remediation_mode)
    
    if self_signed_results:  # Add this block
        print_self_signed_results(self_signed_results, remediation_mode)
        
    if expired_cert_results:
        print_expired_cert_results(expired_cert_results, remediation_mode)

    # Print overall summary
    print(f"\n{Fore.BLUE}[+] Overall Scan Summary:{Style.RESET_ALL}")
    print(f"Total targets: {total_targets}")
    print(f"{Fore.YELLOW}Errors: {error_count}{Style.RESET_ALL}")

def print_vulnerability_results(vuln_name, results, show_all_ciphers, remediation_mode):
    """Print results for cipher suite vulnerabilities (Bar Mitzvah, SWEET32)"""
    vulnerable_count = sum(1 for _, is_vulnerable, _ in results if is_vulnerable)

    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.BLUE}[+] {vuln_name} Vulnerability Scan Results:")
    print(f"{Fore.BLUE}{'=' * 60}")

    if remediation_mode:
        print(f"\n{Fore.CYAN}[*] Remediation Test Results:\n")

        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"{Fore.YELLOW}[!] Hosts still vulnerable to {vuln_name}:\n")
            for target, is_vulnerable, result in results:
                if is_vulnerable:
                    print(f"{Fore.YELLOW}    {target} - {Fore.RED}NOT REMEDIATED")

                    # For Bar Mitzvah, show RC4 ciphers
                    if vuln_name.startswith("Bar Mitzvah"):
                        for protocol, ciphers in result["rc4_vulnerable_by_protocol"].items():
                            print(f"      {Fore.RED}Accepted {protocol} RC4 Cipher Suites:")
                            for cipher in ciphers:
                                print(f"        - {cipher['name']} ({cipher['bits']} bits)")

                    # For SWEET32, show 3DES ciphers
                    if vuln_name.startswith("SWEET32"):
                        for protocol, ciphers in result["sweet32_vulnerable_by_protocol"].items():
                            print(f"      {Fore.RED}Accepted {protocol} 3DES Cipher Suites:")
                            for cipher in ciphers:
                                print(f"        - {cipher['name']} ({cipher['bits']} bits)")

        # Print remediated hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts remediated for {vuln_name}:\n")
            for target, is_vulnerable, _ in results:
                if not is_vulnerable:
                    print(f"{Fore.GREEN}    {target} - REMEDIATED")
    else:
        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}[!] Hosts vulnerable to {vuln_name}:\n")
            for target, is_vulnerable, result in results:
                if is_vulnerable:
                    print(f"{Fore.YELLOW}[!] {target} is vulnerable to {vuln_name}")

                    # For Bar Mitzvah, show RC4 ciphers
                    if vuln_name.startswith("Bar Mitzvah"):
                        for protocol, ciphers in result["rc4_vulnerable_by_protocol"].items():
                            print(f"    {Fore.RED}Accepted {protocol} RC4 Cipher Suites:")
                            for cipher in ciphers:
                                print(f"      - {cipher['name']} ({cipher['bits']} bits)")

                    # For SWEET32, show 3DES ciphers
                    if vuln_name.startswith("SWEET32"):
                        for protocol, ciphers in result["sweet32_vulnerable_by_protocol"].items():
                            print(f"    {Fore.RED}Accepted {protocol} 3DES Cipher Suites:")
                            for cipher in ciphers:
                                print(f"      - {cipher['name']} ({cipher['bits']} bits)")

                    # Show all ciphers if requested
                    if show_all_ciphers:
                        print(f"\n    {Fore.BLUE}All Supported Cipher Suites:")
                        for protocol in sorted(result["protocol_ciphers"].keys()):
                            print(f"    {Fore.BLUE}{protocol}:")
                            for cipher in result["protocol_ciphers"][protocol]:
                                print(f"      - {cipher['name']} ({cipher['bits']} bits)")

        # Print non-vulnerable hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts not vulnerable to {vuln_name}:\n")
            for target, is_vulnerable, result in results:
                if not is_vulnerable:
                    print(f"{Fore.GREEN}[✓] {target} is not vulnerable to {vuln_name}")

                    # Show all ciphers if requested
                    if show_all_ciphers:
                        print(f"    {Fore.BLUE}All Supported Cipher Suites:")
                        for protocol in sorted(result["protocol_ciphers"].keys()):
                            print(f"    {Fore.BLUE}{protocol}:")
                            for cipher in result["protocol_ciphers"][protocol]:
                                print(f"      - {cipher['name']} ({cipher['bits']} bits)")

    # Print summary
    print(f"\n{Fore.BLUE}[+] {vuln_name} Scan Summary:")
    print(f"Total targets: {len(results)}")
    print(f"{Fore.RED}Vulnerable: {vulnerable_count}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Not vulnerable: {len(results) - vulnerable_count}{Style.RESET_ALL}")

def print_self_signed_results(results, remediation_mode):
    """Print results for self-signed certificate checks"""
    vulnerable_count = sum(1 for _, is_self_signed, _ in results if is_self_signed)

    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.BLUE}[+] Self-Signed Certificate Scan Results:")
    print(f"{Fore.BLUE}{'=' * 60}")

    if remediation_mode:
        print(f"\n{Fore.CYAN}[*] Remediation Test Results:\n")

        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"{Fore.YELLOW}[!] Hosts still using self-signed certificates:\n")
            for target, is_self_signed, result in results:
                if is_self_signed:
                    print(f"{Fore.YELLOW}    {target} - {Fore.RED}NOT REMEDIATED")
                    print(f"      Subject: {result['subject']}")
                    print(f"      Issuer: {result['issuer']}")

        # Print remediated hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with properly signed certificates:\n")
            for target, is_self_signed, result in results:
                if not is_self_signed:
                    print(f"{Fore.GREEN}    {target} - REMEDIATED")
                    print(f"      Subject: {result['subject']}")
                    print(f"      Issuer: {result['issuer']}")
    else:
        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}[!] Hosts using self-signed certificates:\n")
            for target, is_self_signed, result in results:
                if is_self_signed:
                    print(f"{Fore.RED}[✗] SELF-SIGNED - VULNERABLE: {target}")
                    print(f"    Subject: {result['subject']}")
                    print(f"    Issuer: {result['issuer']}")

        # Print non-vulnerable hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with properly signed certificates:\n")
            for target, is_self_signed, result in results:
                if not is_self_signed:
                    print(f"{Fore.GREEN}[✓] NOT SELF-SIGNED: {target}")
                    print(f"    Subject: {result['subject']}")
                    print(f"    Issuer: {result['issuer']}")

    # Print summary
    print(f"\n{Fore.BLUE}[+] Self-Signed Certificate Scan Summary:")
    print(f"Total targets: {len(results)}")
    print(f"{Fore.RED}Self-signed certificates: {vulnerable_count}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Properly signed certificates: {len(results) - vulnerable_count}{Style.RESET_ALL}")


def print_signature_results(results, remediation_mode):
    """Print results for weak signature algorithm checks"""
    vulnerable_count = sum(1 for _, is_vulnerable, _ in results if is_vulnerable)

    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.BLUE}[+] Weak Signature Algorithm Scan Results:")
    print(f"{Fore.BLUE}{'=' * 60}")

    if remediation_mode:
        print(f"\n{Fore.CYAN}[*] Remediation Test Results:\n")

        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"{Fore.YELLOW}[!] Hosts still using weak signature algorithms:\n")
            for target, is_vulnerable, result in results:
                if is_vulnerable:
                    print(f"{Fore.YELLOW}    {target} - {Fore.RED}NOT REMEDIATED - Using {result['signature_algorithm']}")

        # Print remediated hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with secure signature algorithms:\n")
            for target, is_vulnerable, result in results:
                if not is_vulnerable:
                    print(f"{Fore.GREEN}    {target} - REMEDIATED - Using {result['signature_algorithm']}")
    else:
        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}[!] Hosts using weak signature algorithms:\n")
            for target, is_vulnerable, result in results:
                if is_vulnerable:
                    print(f"{Fore.RED}[✗] WEAK HASH - VULNERABLE: {target} uses {result['signature_algorithm']}")

        # Print non-vulnerable hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts using secure signature algorithms:\n")
            for target, is_vulnerable, result in results:
                if not is_vulnerable:
                    print(f"{Fore.GREEN}[✓] NOT VULNERABLE: {target} uses {result['signature_algorithm']}")

    # Print summary
    print(f"\n{Fore.BLUE}[+] Weak Signature Algorithm Scan Summary:")
    print(f"Total targets: {len(results)}")
    print(f"{Fore.RED}Vulnerable: {vulnerable_count}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Not vulnerable: {len(results) - vulnerable_count}{Style.RESET_ALL}")

def print_tls_results(tls_version, results, remediation_mode):
    """Print results for TLS version checks"""
    vulnerable_count = sum(1 for _, is_enabled, _ in results if is_enabled)

    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.BLUE}[+] {tls_version} Support Scan Results:")
    print(f"{Fore.BLUE}{'=' * 60}")

    if remediation_mode:
        print(f"\n{Fore.CYAN}[*] Remediation Test Results:\n")

        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"{Fore.YELLOW}[!] Hosts with {tls_version} still ENABLED:\n")
            for target, is_enabled, _ in results:
                if is_enabled:
                    print(f"{Fore.YELLOW}    {target} - {Fore.RED}NOT REMEDIATED")

        # Print remediated hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with {tls_version} disabled:\n")
            for target, is_enabled, _ in results:
                if not is_enabled:
                    print(f"{Fore.GREEN}    {target} - REMEDIATED")
    else:
        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}[!] Hosts with {tls_version} ENABLED:\n")
            for target, is_enabled, _ in results:
                if is_enabled:
                    print(f"{Fore.YELLOW}    - {target}")
        else:
            print(f"\n{Fore.GREEN}[✓] No hosts were found with {tls_version} enabled.")

        # Print non-vulnerable hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with {tls_version} DISABLED:\n")
            for target, is_enabled, _ in results:
                if not is_enabled:
                    print(f"{Fore.GREEN}    - {target}")

    # Print summary
    print(f"\n{Fore.BLUE}[+] {tls_version} Support Scan Summary:")
    print(f"Total targets: {len(results)}")
    print(f"{Fore.YELLOW}Hosts with {tls_version} enabled: {vulnerable_count}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Hosts with {tls_version} disabled: {len(results) - vulnerable_count}{Style.RESET_ALL}")
    
def print_expired_cert_results(results, remediation_mode):
    """Print results for expired certificate checks"""
    vulnerable_count = sum(1 for _, is_expired, _ in results if is_expired)

    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.BLUE}[+] SSL Certificate Expiration Scan Results:")
    print(f"{Fore.BLUE}{'=' * 60}")

    if remediation_mode:
        print(f"\n{Fore.CYAN}[*] Remediation Test Results:\n")

        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"{Fore.YELLOW}[!] Hosts with expired certificates:\n")
            for target, is_expired, result in results:
                if is_expired:
                    print(f"{Fore.YELLOW}    {target} - {Fore.RED}NOT REMEDIATED")
                    print(f"      Expired on: {result['expiration_date_str']}")

        # Print remediated hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with valid certificates:\n")
            for target, is_expired, result in results:
                if not is_expired:
                    print(f"{Fore.GREEN}    {target} - REMEDIATED")
                    print(f"      Expires in: {result['days_remaining']} days ({result['expiration_date_str']})")
    else:
        # Print vulnerable hosts
        if vulnerable_count > 0:
            print(f"\n{Fore.YELLOW}[!] Hosts with expired certificates:\n")
            for target, is_expired, result in results:
                if is_expired:
                    print(f"{Fore.RED}[✗] EXPIRED SSL CERTIFICATE - VULNERABLE: {target}")
                    print(f"    Expired on: {result['expiration_date_str']}")

        # Print non-vulnerable hosts
        if vulnerable_count < len(results):
            print(f"\n{Fore.GREEN}[+] Hosts with valid certificates:\n")
            for target, is_expired, result in results:
                if not is_expired:
                    print(f"{Fore.GREEN}[✓] CURRENT SSL CERTIFICATE - NOT VULNERABLE: {target}")
                    print(f"    Expires in: {result['days_remaining']} days ({result['expiration_date_str']})")

    # Print summary
    print(f"\n{Fore.BLUE}[+] SSL Certificate Expiration Scan Summary:")
    print(f"Total targets: {len(results)}")
    print(f"{Fore.RED}Expired certificates: {vulnerable_count}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Valid certificates: {len(results) - vulnerable_count}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Types:
  --bar-mitzvah    Check for Bar Mitzvah vulnerability (RC4 ciphers)
  --sweet32        Check for SWEET32 vulnerability (3DES ciphers)
  --weak-signature Check for weak signature algorithms (MD5, SHA1)
  --tls10          Check for TLSv1.0 support
  --tls11          Check for TLSv1.1 support
  --self-signed    Check for self-signed certificates
  --expired-cert   Check for expired SSL certificat
  --all            Run all scan types (default)

Examples:
  python sslscan2.0.py -i targets.txt --all
  python sslscan2.0.py -i targets.txt --bar-mitzvah --sweet32 -t 10
  python sslscan2.0.py -i targets.txt --tls10 --tls11 -r
  python sslscan2.0.py -i targets.txt --self-signed
  python sslscan2.0.py -i targets.txt --expired-cert
"""
    )

    parser.add_argument("-i", "--input", required=True, help="Input file with IP:PORT targets, one per line")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("-r", "--remediation", action="store_true", help="Run in remediation test mode")
    parser.add_argument("--show-all-ciphers", action="store_true", help="Show all supported cipher suites, not just vulnerable ones")

    # Scan type options
    scan_group = parser.add_argument_group("scan types")
    scan_group.add_argument("--bar-mitzvah", action="store_true", help="Check for Bar Mitzvah vulnerability (RC4 ciphers)")
    scan_group.add_argument("--sweet32", action="store_true", help="Check for SWEET32 vulnerability (3DES ciphers)")
    scan_group.add_argument("--weak-signature", action="store_true", help="Check for weak signature algorithms (MD5, SHA1)")
    scan_group.add_argument("--tls10", action="store_true", help="Check for TLSv1.0 support")
    scan_group.add_argument("--tls11", action="store_true", help="Check for TLSv1.1 support")
    scan_group.add_argument("--self-signed", action="store_true", help="Check for self-signed certificates")
    scan_group.add_argument("--all", action="store_true", help="Run all scan types (default)")
    scan_group.add_argument("--expired-cert", action="store_true", help="Check for expired SSL certificates")

    args = parser.parse_args()

    # Determine which scan types to run
    scan_types = []
    if args.bar_mitzvah or args.all:
        scan_types.append("bar_mitzvah")
    if args.sweet32 or args.all:
        scan_types.append("sweet32")
    if args.weak_signature or args.all:
        scan_types.append("weak_signature")
    if args.tls10 or args.all:
        scan_types.append("tls10")
    if args.tls11 or args.all:
        scan_types.append("tls11")
    if args.self_signed or args.all:  # Add this block
        scan_types.append("self_signed")
    if args.expired_cert or args.all:
        scan_types.append("expired_cert")

    # If no scan types specified, run all
    if not scan_types:
        scan_types = ["bar_mitzvah", "sweet32", "weak_signature", "tls10", "tls11", "self_signed", "expired_cert"]

    # Load targets
    targets = load_targets(args.input)

    if not targets:
        print(f"{Fore.YELLOW}Warning: No targets found in input file{Style.RESET_ALL}")
        return

    with print_lock:
        print(f"{Fore.BLUE}[+] Loaded {len(targets)} targets from {args.input}")
        print(f"{Fore.BLUE}[+] Running scan types: {', '.join(scan_types).replace('_', ' ')}")
        print(f"{Fore.BLUE}[+] Using {args.threads} concurrent threads")
        if args.remediation:
            print(f"{Fore.BLUE}[+] Running in remediation test mode")
        print()

    # Run scans in parallel
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_target = {executor.submit(scan_target, ip, port, scan_types): (ip, port) for ip, port in targets}

        for future in concurrent.futures.as_completed(future_to_target):
            result = future.result()
            if result:
                results.append(result)

    # Print results
    print_scan_results(results, args.show_all_ciphers, args.remediation)

if __name__ == "__main__":
    main()
