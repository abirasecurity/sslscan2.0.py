# sslscan2.0.py
SSLScan2.0 is a comprehensive Python-based tool for scanning SSL/TLS configurations and identifying common vulnerabilities in web servers. It leverages the sslscan command-line utility to perform detailed analysis of SSL/TLS implementations.

# Features

1. Multiple Vulnerability Checks:
	1. Bar Mitzvah (RC4 ciphers)
	2. SWEET32 (3DES ciphers)
	3. Weak signature algorithms (MD5, SHA1)
	4. TLSv1.0 and TLSv1.1 support
	5. Self-signed certificates
	6. Expired certificates

2. Flexible Input Options:
    1. Scan multiple targets from a file
    2. Scan a single target directly
    3. Concurrent scanning with configurable thread count

3. Rich Output Formats:
    1. Colorized console output
    2. JSON, CSV, XML, and YAML export options
    3. Detailed vulnerability reporting

4. Remediation Testing:
    1. Track which vulnerabilities have been fixed
    2. Compare scan results over time


# Requirements

1. Python 3.6+
2. ```sslscan``` command-line tool
3. Python packages: ```colorama``` and ```pyyaml```

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

4. Install required Python packages:

```
pip install colorama pyyaml
```

5. Download the script and make it executable:

```
chmod +x sslscan2.0.py
```

# Usage

## Basic Usage

```
python sslscan2.0.py -s example.com:443 --all
```

## Scan Multiple Targets

```
python sslscan2.0.py -i targets.txt --all
```

Where targets.txt contains one target per line in the format IP:PORT or hostname:POR

## Specific Vulnerability Checks

```
python sslscan2.0.py -i targets.txt --bar-mitzvah --sweet32 --tls10
```

## Concurrent Scanning

```
python sslscan2.0.py -i targets.txt --all -t 10
```

## Output Options

```
# JSON output
python sslscan2.0.py -i targets.txt --all -o results.json

# CSV output
python sslscan2.0.py -i targets.txt --all -o results.csv --format csv

# XML output
python sslscan2.0.py -i targets.txt --all -o results.xml --format xml

# YAML output
python sslscan2.0.py -i targets.txt --all -o results.yaml --format yaml

# Suppress console output
python sslscan2.0.py -i targets.txt --all -o results.json --no-console
```

## Command-Line Options

```
Input Options:
  -i, --input      Input file with IP:PORT targets, one per line
  -s, --single     Single target in IP:PORT format
  -t, --threads    Number of concurrent threads (default: 5)

Scan Types:
  --bar-mitzvah    Check for Bar Mitzvah vulnerability (RC4 ciphers)
  --sweet32        Check for SWEET32 vulnerability (3DES ciphers)
  --weak-signature Check for weak signature algorithms (MD5, SHA1)
  --tls10          Check for TLSv1.0 support
  --tls11          Check for TLSv1.1 support
  --self-signed    Check for self-signed certificates
  --expired-cert   Check for expired SSL certificates
  --all            Run all scan types (default)

Output Options:
  -o, --output     Specify output file path
  --format         Output format (json, csv, xml, yaml)
  --no-console     Suppress console output and only write to file
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
