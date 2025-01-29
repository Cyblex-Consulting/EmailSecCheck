# What is EmailSecCheck?
EmailSecCheck is a lightweight Python utility that checks whether email security DNS records (DMARC and SPF) are configured properly for a domain. EmailSecCheck is powered by [checkdmarc](https://github.com/domainaware/checkdmarc), and leverages it to identify common misconfigurations in DNS records that may enable for email spoofing.

Email spoofing is identified under the following conditions:

 - SPF Issues
   - SPF configured as something other than `fail` or `softfail`
   - SPF record is missing
   - SPF record contains a syntax error
 - DMARC Issues
   - Multiple SPF records exist
   - DMARC record is missing
   - DMARC record contains a syntax error
   - Multiple DMARC records exist

An additional check can be performed to verify if a set of includes is present in the SPF with the `--spf-mandatory-include` flag.

# Getting Started
Grab the latest release and install the package requirements by running `pip3 install -r requirements.txt`. EmailSecCheck was developed for Python 3.

## Checking DNS Records for a Single Domain
```
python3 emailseccheck.py --domain <domain_here>
```

## Checking DNS Records for Several Domains
```
python3 emailseccheck.py --domains_file <path_to_file_here>
```

## Usage
```
usage: emailseccheck.py [-h] (--domain DOMAIN | --domains_file DOMAINS_FILE) [-v] [-os | -od] [--spf-mandatory-include [SPF_MANDATORY_INCLUDE ...]]

options:
  -h, --help            show this help message and exit
  --domain DOMAIN       Domain to check for SPF/DMARC issues (default: None)
  --domains_file DOMAINS_FILE
                        File containing list of domains to check for SPF/DMARC issues (default: None)
  -v, --verbose         Show verbose output (default: False)
  -os, --only-spf       Only check SPF (default: False)
  -od, --only-dmarc     Only check DMARC (default: False)
  --spf-mandatory-include [SPF_MANDATORY_INCLUDE ...]
                        Verify that this specific spf include is present (Example: spf.protection.outlook.com) (default: None)
```