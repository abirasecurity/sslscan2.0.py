# sslscan2.0.py
A comprehensive tool for scanning SSL/TLS configurations for common vulnerabilities and misconfigurations.

# Overview

This tool combines multiple SSL/TLS scanning capabilities into a single unified interface. It uses sslscan to check target systems for various vulnerabilities and insecure configurations, including:

1. Bar Mitzvah Vulnerability: Detects RC4 cipher suites
2. SWEET32 Vulnerability: Detects 3DES cipher suites
3. Weak Signature Algorithms: Detects MD5 and SHA1 signature algorithms
4. Outdated Protocol Support: Detects TLSv1.0 and TLSv1.1 support

# Features

1. Unified Interface: Single command-line tool for multiple SSL/TLS checks
2. Concurrent Scanning: Multi-threaded scanning for faster results
3. Detailed Reporting: Comprehensive output with vulnerability details
4. Remediation Mode: Track remediation progress across multiple scans
5. Colorized Output: Easy-to-read color-coded results

# Requirements

1. Python 3.6+
2. ```sslscan``` command-line tool
3. Python packages: ```colorama```

# Installation

1. Ensure you have Python 3.6+ installed
2. Install the required sslscan tool:

```
# Debian/Ubuntu
sudo apt-get install sslscan

# RHEL/CentOS
sudo yum install sslscan

# macOS
brew install sslscan
```

3. Install required Python packages:

```
pip install colorama
```

4. Download the script and make it executable:

```
chmod +x sslscan2.0.py
```

# Usage

## Basic Usage

```
python sslscan2.0.py -i targets.txt
```

This will run all scan types against the targets listed in ```targets.txt.```

## Input File Format

The input file should contain one target per line in the format ```IP:PORT```. If no port is specified, the default port 443 will be used.

Example ```targets.txt```:

```
192.168.1.1:443
10.0.0.1:8443
example.com
internal-server:8080
```

## Command-Line Options

```
usage: sslscan2.0.py [-h] -i INPUT [-t THREADS] [-r] [--show-all-ciphers]
                      [--bar-mitzvah] [--sweet32] [--weak-signature] [--tls10]
                      [--tls11] [--all]

SSL/TLS Vulnerability Scanner

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file with IP:PORT targets, one per line
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 5)
  -r, --remediation     Run in remediation test mode
  --show-all-ciphers    Show all supported cipher suites, not just vulnerable ones

scan types:
  --bar-mitzvah         Check for Bar Mitzvah vulnerability (RC4 ciphers)
  --sweet32             Check for SWEET32 vulnerability (3DES ciphers)
  --weak-signature      Check for weak signature algorithms (MD5, SHA1)
  --tls10               Check for TLSv1.0 support
  --tls11               Check for TLSv1.1 support
  --all                 Run all scan types (default)
```

## Examples

Run all scan types:

```
python sslscan2.0.py -i targets.txt --all
```

Check only for RC4 and 3DES vulnerabilities with 10 concurrent threads:

```
python sslscan2.0.py -i targets.txt --bar-mitzvah --sweet32 -t 10
```

Check for TLSv1.0 and TLSv1.1 support in remediation mode:

```
python sslscan2.0.py -i targets.txt --tls10 --tls11 -r
```

Show all supported cipher suites for each target:

```
python sslscan2.0.py -i targets.txt --bar-mitzvah --show-all-ciphers

```

# Scan Types

## Bar Mitzvah (RC4)

Checks for the presence of RC4 cipher suites, which are vulnerable to the "Bar Mitzvah" attack. RC4 is considered cryptographically weak and should not be used.

## SWEET32 (3DES)

Checks for the presence of 3DES (Triple DES) cipher suites, which are vulnerable to the "SWEET32" birthday attack. 3DES uses a 64-bit block size, making it susceptible to birthday attacks in long-lived connections.

## Weak Signature Algorithms

Checks for certificates using weak signature algorithms:

1. MD5 (completely broken)
2. SHA1 (cryptographically weak)

## TLSv1.0 Support

Checks if the server supports TLSv1.0, which is considered outdated and insecure. PCI DSS compliance requires disabling TLSv1.0.

## TLSv1.1 Support

Checks if the server supports TLSv1.1, which is also considered outdated. Modern servers should use TLSv1.2 or TLSv1.3.

## Remediation Mode

The remediation mode (-r flag) is designed to help track progress when fixing vulnerabilities. It categorizes hosts as:

1. NOT REMEDIATED: Still vulnerable
2. REMEDIATED: Previously vulnerable but now fixed

This is useful for follow-up scans after remediation efforts.

# Output

##  --bar-mitzvah Flag (RC4 Vulnerability)

```
[+] Loaded 3 targets from targets.txt
[+] Running scan types: bar_mitzvah
[+] Using 5 concurrent threads

[+] Scanning 192.168.1.1:443...
[+] Scanning 192.168.1.2:443...
[+] Scanning 192.168.1.3:443...

============================================================
[+] Bar Mitzvah (RC4) Vulnerability Scan Results:
============================================================

[!] Hosts vulnerable to Bar Mitzvah:

[!] 192.168.1.1:443 is vulnerable to Bar Mitzvah
    Accepted TLSv1.0 RC4 Cipher Suites:
      - RC4-SHA (128 bits)
      - RC4-MD5 (128 bits)

[+] Hosts not vulnerable to Bar Mitzvah:

[✓] 192.168.1.2:443 is not vulnerable to Bar Mitzvah
[✓] 192.168.1.3:443 is not vulnerable to Bar Mitzvah

[+] Bar Mitzvah Scan Summary:
Total targets: 3
Vulnerable: 1
Not vulnerable: 2

[+] Overall Scan Summary:
Total targets: 3
Errors: 0
```

## --sweet32 Flag (3DES Vulnerability)

```
[+] Loaded 3 targets from targets.txt
[+] Running scan types: sweet32
[+] Using 5 concurrent threads

[+] Scanning 192.168.1.1:443...
[+] Scanning 192.168.1.2:443...
[+] Scanning 192.168.1.3:443...

============================================================
[+] SWEET32 (3DES) Vulnerability Scan Results:
============================================================

[!] Hosts vulnerable to SWEET32:

[!] 192.168.1.2:443 is vulnerable to SWEET32
    Accepted TLSv1.0 3DES Cipher Suites:
      - DES-CBC3-SHA (168 bits)
    Accepted TLSv1.1 3DES Cipher Suites:
      - DES-CBC3-SHA (168 bits)

[+] Hosts not vulnerable to SWEET32:

[✓] 192.168.1.1:443 is not vulnerable to SWEET32
[✓] 192.168.1.3:443 is not vulnerable to SWEET32

[+] SWEET32 Scan Summary:
Total targets: 3
Vulnerable: 1
Not vulnerable: 2

[+] Overall Scan Summary:
Total targets: 3
Errors: 0
```

##  --weak-signature Flag

```
[+] Loaded 3 targets from targets.txt
[+] Running scan types: weak signature
[+] Using 5 concurrent threads

[+] Scanning 192.168.1.1:443...
[+] Scanning 192.168.1.2:443...
[+] Scanning 192.168.1.3:443...

============================================================
[+] Weak Signature Algorithm Scan Results:
============================================================

[!] Hosts using weak signature algorithms:

[✗] WEAK HASH - VULNERABLE: 192.168.1.3:443 uses sha1WithRSAEncryption

[+] Hosts using secure signature algorithms:

[✓] NOT VULNERABLE: 192.168.1.1:443 uses sha256WithRSAEncryption
[✓] NOT VULNERABLE: 192.168.1.2:443 uses sha256WithRSAEncryption

[+] Weak Signature Algorithm Scan Summary:
Total targets: 3
Vulnerable: 1
Not vulnerable: 2

[+] Overall Scan Summary:
Total targets: 3
Errors: 0
```

##  --tls10 Flag

```
[+] Loaded 3 targets from targets.txt
[+] Running scan types: tls10
[+] Using 5 concurrent threads

[+] Scanning 192.168.1.1:443...
[+] Scanning 192.168.1.2:443...
[+] Scanning 192.168.1.3:443...

============================================================
[+] TLSv1.0 Support Scan Results:
============================================================

[!] Hosts with TLSv1.0 ENABLED:

    - 192.168.1.1:443
    - 192.168.1.2:443

[+] Hosts with TLSv1.0 DISABLED:

    - 192.168.1.3:443

[+] TLSv1.0 Support Scan Summary:
Total targets: 3
Hosts with TLSv1.0 enabled: 2
Hosts with TLSv1.0 disabled: 1

[+] Overall Scan Summary:
Total targets: 3
Errors: 0
```

## --tls11 Flag

```
[+] Loaded 3 targets from targets.txt
[+] Running scan types: tls11
[+] Using 5 concurrent threads

[+] Scanning 192.168.1.1:443...
[+] Scanning 192.168.1.2:443...
[+] Scanning 192.168.1.3:443...

============================================================
[+] TLSv1.1 Support Scan Results:
============================================================

[!] Hosts with TLSv1.1 ENABLED:

    - 192.168.1.2:443

[+] Hosts with TLSv1.1 DISABLED:

    - 192.168.1.1:443
    - 192.168.1.3:443

[+] TLSv1.1 Support Scan Summary:
Total targets: 3
Hosts with TLSv1.1 enabled: 1
Hosts with TLSv1.1 disabled: 2

[+] Overall Scan Summary:
Total targets: 3
Errors: 0
```

## --all Flag (All Scan Types)

```
[+] Loaded 3 targets from targets.txt
[+] Running scan types: bar_mitzvah, sweet32, weak_signature, tls10, tls11
[+] Using 5 concurrent threads

[+] Scanning 192.168.1.1:443...
[+] Scanning 192.168.1.2:443...
[+] Scanning 192.168.1.3:443...

============================================================
[+] Bar Mitzvah (RC4) Vulnerability Scan Results:
============================================================

[!] Hosts vulnerable to Bar Mitzvah:

[!] 192.168.1.1:443 is vulnerable to Bar Mitzvah
    Accepted TLSv1.0 RC4 Cipher Suites:
      - RC4-SHA (128 bits)
      - RC4-MD5 (128 bits)

[+] Hosts not vulnerable to Bar Mitzvah:

[✓] 192.168.1.2:443 is not vulnerable to Bar Mitzvah
[✓] 192.168.1.3:443 is not vulnerable to Bar Mitzvah

[+] Bar Mitzvah Scan Summary:
Total targets: 3
Vulnerable: 1
Not vulnerable: 2

============================================================
[+] SWEET32 (3DES) Vulnerability Scan Results:
============================================================

[!] Hosts vulnerable to SWEET32:

[!] 192.168.1.2:443 is vulnerable to SWEET32
    Accepted TLSv1.0 3DES Cipher Suites:
      - DES-CBC3-SHA (168 bits)
    Accepted TLSv1.1 3DES Cipher Suites:
      - DES-CBC3-SHA (168 bits)

[+] Hosts not vulnerable to SWEET32:

[✓] 192.168.1.1:443 is not vulnerable to SWEET32
[✓] 192.168.1.3:443 is not vulnerable to SWEET32

[+] SWEET32 Scan Summary:
Total targets: 3
Vulnerable: 1
Not vulnerable: 2

============================================================
[+] Weak Signature Algorithm Scan Results:
============================================================

[!] Hosts using weak signature algorithms:

[✗] WEAK HASH - VULNERABLE: 192.168.1.3:443 uses sha1WithRSAEncryption

[+] Hosts using secure signature algorithms:

[✓] NOT VULNERABLE: 192.168.1.1:443 uses sha256WithRSAEncryption
[✓] NOT VULNERABLE: 192.168.1.2:443 uses sha256WithRSAEncryption

[+] Weak Signature Algorithm Scan Summary:
Total targets: 3
Vulnerable: 1
Not vulnerable: 2

============================================================
[+] TLSv1.0 Support Scan Results:
============================================================

[!] Hosts with TLSv1.0 ENABLED:

    - 192.168.1.1:443
    - 192.168.1.2:443

[+] Hosts with TLSv1.0 DISABLED:

    - 192.168.1.3:443

[+] TLSv1.0 Support Scan Summary:
Total targets: 3
Hosts with TLSv1.0 enabled: 2
Hosts with TLSv1.0 disabled: 1

============================================================
[+] TLSv1.1 Support Scan Results:
============================================================

[!] Hosts with TLSv1.1 ENABLED:

    - 192.168.1.2:443

[+] Hosts with TLSv1.1 DISABLED:

    - 192.168.1.1:443
    - 192.168.1.3:443

[+] TLSv1.1 Support Scan Summary:
Total targets: 3
Hosts with TLSv1.1 enabled: 1
Hosts with TLSv1.1 disabled: 2

[+] Overall Scan Summary:
Total targets: 3
Errors: 0
```

# Ethical Usage

This tool is intended for:

1. Security professionals conducting authorized penetration tests
2. Website owners testing their own sites for vulnerabilities
3. Educational purposes to understand clickjacking protections

Always obtain proper authorization before testing any website you don't own

# License

MIT License

# Contributing

Contributions are welcome! Please feel free to submit a Pull Request
