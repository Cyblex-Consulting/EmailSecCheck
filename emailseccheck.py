import validators.domain as validate_domain
import checkdmarc
from colorama import Fore
import os
import sys
import argparse


def initialize():
    global args
    
    parser = argparse.ArgumentParser(
        prog="emailseccheck.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    domain_argument_group = parser.add_mutually_exclusive_group(required=True)
    domain_argument_group.add_argument("--domain", type=str,
                                       help="Domain to check for SPF/DMARC issues")
    domain_argument_group.add_argument("--domains_file", type=str,
                                       help="File containing list of domains to check for SPF/DMARC issues")

    parser.add_argument("-v", "--verbose", help="Show verbose output", action="store_true")
    
    record_type_argument_group = parser.add_mutually_exclusive_group(required=False)
    record_type_argument_group.add_argument("-os", "--only-spf", help="Only check SPF", action="store_true")
    record_type_argument_group.add_argument("-od", "--only-dmarc", help="Only check DMARC", action="store_true")

    parser.add_argument("--spf-mandatory-include", type=str,
                                       help="Verify that this specific spf include is present (Example: spf.protection.outlook.com)", nargs="*")

    args = parser.parse_args()
    main(args)


def main(args):
    validate_args(args)

    domains_list = []
    spf_to_include = []

    if args.domain:
        domains_list.append(args.domain)
    else:
        with open(args.domains_file, "r") as domains_file:
            domains_file_content = domains_file.readlines()
            domains_list.extend(domains_file_content)

    domains_list = cleanup_domains_list(domains_list)

    if len(domains_list) > 0:
        check_domain_security(domains_list)
    else:
        print_error("No domain(s) were provided")

    if args.spf_mandatory_include:
        # TODO check the format
        spf_to_include.extend(args.spf_mandatory_include)
        pass

def cleanup_domains_list(domains_list):
    domains_list = [d.lower() for d in domains_list]
    domains_list = list(dict.fromkeys(domains_list))

    domains_list.sort()
    return domains_list

def validate_spf_include(data):
    # TODO check the format
    return True

def validate_args(args):
    domain_arg_valid = args.domain is None or validate_domain(args.domain)
    domain_file_arg_valid = args.domains_file is None or os.path.isfile(
        args.domains_file)
    spf_include_arg_valid = args.spf_mandatory_include is None or validate_spf_include(args.spf_mandatory_include)

    if not domain_arg_valid:
        print_warning("Domain is not valid. Is it formatted correctly?")
    elif not domain_file_arg_valid:
        print_warning("Domain file is not valid. Does it exist?")

    valid_args = domain_arg_valid and domain_file_arg_valid and spf_include_arg_valid
    if not valid_args:
        print_error("Arguments are invalid.")
        sys.exit(1)

    return valid_args


def validate_provided_domains(domains):
    for domain in domains:
        if not validate_domain(domain):
            print_error("Invalid domain provided (%s)" % domain)
            sys.exit(1)


def check_domain_security(domains):
    global args
    print_info("Analyzing %d domain(s)..." % len(domains), new_section=True)

    spoofable_domains = []
    error_no_spf_domains = []
    error_spf_validity_domains = []
    error_spf_include_domains = []
    error_spf_policy_domains = []
    error_no_dmarc_domains = []
    error_dmarc_validity_domains = []
    error_dmarc_policy_domains = []

    for domain in domains:
        domain = domain.strip()
        print_info("Analyzing %s" % domain, new_section=True)

        spoofing_possible_spf = False
        spoofing_possible_dmarc = False

        # Check SPF
        if args.only_dmarc:
            pass
        else:
            try:
                spf_results = checkdmarc.get_spf_record(domain)

                spf_value = spf_results["parsed"]["all"]
                
                print_verbose("SPF Record : %s" % spf_results["record"])

                if spf_value != 'fail':
                    spoofing_possible_spf = True
                    if spf_value == "softfail":
                        print_warning(
                            "SPF record configured to 'softfail' for '%s'" % domain)
                        if domain not in error_spf_policy_domains:
                            error_spf_policy_domains.append(domain)
                    else:
                        print_warning(
                            "SPF record missing failure behavior value for '%s'" % domain)
                        if domain not in error_spf_policy_domains:
                            error_spf_policy_domains.append(domain)
                else:
                    additional_checks_success = True
                    if args.spf_mandatory_include:
                        
                        if "include" not in spf_results["parsed"].keys():
                            print_warning(
                                "No include in SPF record for '%s'" % domain)
                            if domain not in error_spf_include_domains:
                                error_spf_include_domains.append(domain)
                        else:
                            for mandatory_domain in args.spf_mandatory_include:
                                success = False
                                for included_domain in spf_results["parsed"]["include"]:
                                    if mandatory_domain == included_domain["domain"]:
                                        success = True
                                        break
                                if not success:
                                    print_warning(
                                        "'%s' is not included in SPF for '%s'. That is not a security issue but may prevent legitimate hosts to send emails." % (mandatory_domain, domain))
                                    additional_checks_success = False
                                    if domain not in error_spf_include_domains:
                                        error_spf_include_domains.append(domain)
                    if additional_checks_success:
                        print_success("SPF correctly configured for '%s'" % domain)
                    
            except checkdmarc.DNSException:
                print_error(
                    "A general DNS error has occured when performing SPF analysis")
            except checkdmarc.SPFIncludeLoop:
                print_warning(
                    "SPF record contains an 'include' loop for '%s'" % domain)
                if domain not in error_spf_validity_domains:
                    error_spf_validity_domains.append(domain)
            except checkdmarc.SPFRecordNotFound:
                print_warning("SPF record is missing for '%s'" % domain)
                spoofing_possible_spf = True
                if domain not in error_no_spf_domains:
                    error_no_spf_domains.append(domain)
            except checkdmarc.SPFRedirectLoop:
                print_warning(
                    "SPF record contains a 'redirect' loop for '%s'" % domain)
                if domain not in error_spf_validity_domains:
                    error_spf_validity_domains.append(domain)
            except checkdmarc.SPFSyntaxError:
                print_warning(
                    "SPF record contains a syntax error for '%s'" % domain)
                spoofing_possible_spf = True
                if domain not in error_spf_validity_domains:
                    error_spf_validity_domains.append(domain)
            except checkdmarc.SPFTooManyDNSLookups:
                print_warning(
                    "SPF record requires too many DNS lookups for '%s'" % domain)
                if domain not in error_spf_validity_domains:
                    error_spf_validity_domains.append(domain)
            except checkdmarc.MultipleSPFRTXTRecords:
                print_warning(
                    "Multiple SPF records were found for '%s'" % domain)
                spoofing_possible_spf = True
                if domain not in error_spf_validity_domains:
                    error_spf_validity_domains.append(domain)
            
        # Check DMARC
        if args.only_spf:
            pass
        else:
            try:
                dmarc_data = checkdmarc.get_dmarc_record(domain)
                
                print_verbose("DMARC Record : %s" % dmarc_data["record"])
                
                additional_checks_success = True
                # Check policy value
                if not "p" in dmarc_data["parsed"]["tags"].keys():
                    print_warning(
                        "No 'p' value defined in DMARC record for '%s'" % domain)
                    additional_checks_success = False
                    if domain not in error_dmarc_policy_domains:
                        error_dmarc_policy_domains.append(domain)
                else:
                    policy = dmarc_data["parsed"]["tags"]["p"]["value"]
                    if policy == "none":
                        print_warning(
                            "Defined policy is 'none' in DMARC record for '%s'" % domain)
                        additional_checks_success = False
                        if domain not in error_dmarc_policy_domains:
                            error_dmarc_policy_domains.append(domain)
                    elif policy == "quarantine":
                        print_info(
                            "Defined policy is 'quarantine' in DMARC record for '%s'" % domain)
                    elif policy == "reject":
                        pass
                    else:
                        print_warning(
                            "Unknown policy '%s' in DMARC record for '%s'" % (policy, domain))
                        additional_checks_success = False
                        if domain not in error_dmarc_policy_domains:
                            error_dmarc_policy_domains.append(domain)
                        
                # Check pct value
                if not "pct" in dmarc_data["parsed"]["tags"].keys():
                    print_warning(
                        "No 'pct' value defined in DMARC record for '%s'" % domain)
                    additional_checks_success = False
                    if domain not in error_dmarc_policy_domains:
                        error_dmarc_policy_domains.append(domain)
                else:
                    pct = dmarc_data["parsed"]["tags"]["pct"]["value"]
                    if pct != 100:
                        print_warning(
                            "Defined pct is '%i' in DMARC record for '%s'" % (pct, domain))
                        additional_checks_success = False
                        if domain not in error_dmarc_policy_domains:
                            error_dmarc_policy_domains.append(domain)
                    else:
                        if not dmarc_data["parsed"]["tags"]["pct"]["explicit"]:
                            print_info(
                                "Field 'pct' is not explicitly defined in DMARC record for '%s', default value is '%i'" % (domain, pct))

                # Check rua and ruaf values
                for field in ["rua", "ruf"]:
                    if not "rua" in dmarc_data["parsed"]["tags"].keys():
                        print_warning(
                            "No '%s' value defined in DMARC record for '%s'" % (field, domain))
                        additional_checks_success = False
                        if domain not in error_dmarc_policy_domains:
                            error_dmarc_policy_domains.append(domain)
                    else:
                        # TODO check if it is a valid email
                        pass
                
                if additional_checks_success:
                    print_success("DMARC correctly configured for '%s'" % domain)
            except checkdmarc.DNSException:
                print_error(
                    "A general DNS error has occured when performing DMARC analysis")
            except checkdmarc.DMARCRecordInWrongLocation:
                print_warning(
                    "DMARC record is located in the wrong domain for '%s'" % domain)
                if domain not in error_dmarc_validity_domains:
                    error_dmarc_validity_domains.append(domain)
            except checkdmarc.DMARCRecordNotFound:
                print_warning(
                    "DMARC record is missing for '%s'" % domain)
                spoofing_possible_dmarc = True
                if domain not in error_no_dmarc_domains:
                    error_no_dmarc_domains.append(domain)
            except checkdmarc.DMARCReportEmailAddressMissingMXRecords:
                print_warning(
                    "DMARC record's report URI contains a domain with invalid MX records for '%s'" % domain)
                if domain not in error_dmarc_validity_domains:
                    error_dmarc_validity_domains.append(domain)
            except checkdmarc.DMARCSyntaxError:
                print_warning(
                    "DMARC record contains a syntax error for '%s'" % domain)
                spoofing_possible_dmarc = True
                if domain not in error_dmarc_validity_domains:
                    error_dmarc_validity_domains.append(domain)
            except checkdmarc.InvalidDMARCReportURI:
                print_warning(
                    "DMARC record references an invalid report URI for '%s'" % domain)
                if domain not in error_dmarc_validity_domains:
                    error_dmarc_validity_domains.append(domain)
            except checkdmarc.InvalidDMARCTag:
                print_warning(
                    "DMARC record contains an invalid tag for '%s'" % domain)
                
                if domain not in error_dmarc_validity_domains:
                    error_dmarc_validity_domains.append(domain)
            except checkdmarc.MultipleDMARCRecords:
                print_warning(
                    "Multiple DMARC records were found for '%s'" % domain)
                spoofing_possible_dmarc = True
                if domain not in error_dmarc_validity_domains:
                    error_dmarc_validity_domains.append(domain)

        if spoofing_possible_spf or spoofing_possible_dmarc:
            if domain not in spoofable_domains:
                spoofable_domains.append(domain)

    print_info("Finished", new_section=True)

    if len(spoofable_domains) > 0:
        print(Fore.CYAN, "\n\n Spoofing possible for %d domain(s): " %
              len(spoofable_domains))
        for domain in spoofable_domains:
            print(Fore.CYAN, "  > %s" % domain)
    else:
        print(Fore.GREEN, "\n\n No spoofable domains were identified")
    
    if len(error_no_spf_domains) > 0:
        print(Fore.CYAN, "\n\n No SPF record for %d domain(s): " %
              len(error_no_spf_domains))
        for domain in error_no_spf_domains:
            print(Fore.CYAN, "  > %s" % domain)
            
    if len(error_spf_validity_domains) > 0:
        print(Fore.CYAN, "\n\n Invalid SPF records for %d domain(s): " %
              len(error_spf_validity_domains))
        for domain in error_spf_validity_domains:
            print(Fore.CYAN, "  > %s" % domain)
            
    if len(error_spf_policy_domains) > 0:
        print(Fore.CYAN, "\n\n Invalid SPF policy for %d domain(s): " %
              len(error_spf_policy_domains))
        for domain in error_spf_policy_domains:
            print(Fore.CYAN, "  > %s" % domain)
            
    if len(error_spf_include_domains) > 0:
        print(Fore.CYAN, "\n\n Missing SPF includes for %d domain(s): " %
              len(error_spf_include_domains))
        for domain in error_spf_include_domains:
            print(Fore.CYAN, "  > %s" % domain)

    if len(error_no_dmarc_domains) > 0:
        print(Fore.CYAN, "\n\n Missing DMARC records for %d domain(s): " %
              len(error_no_dmarc_domains))
        for domain in error_no_dmarc_domains:
            print(Fore.CYAN, "  > %s" % domain)

    if len(error_dmarc_validity_domains) > 0:
        print(Fore.CYAN, "\n\n Invalid DMARC records for %d domain(s): " %
              len(error_dmarc_validity_domains))
        for domain in error_dmarc_validity_domains:
            print(Fore.CYAN, "  > %s" % domain)
   
    if len(error_dmarc_policy_domains) > 0:
        print(Fore.CYAN, "\n\n Invalid DMARC policy for %d domain(s): " %
              len(error_dmarc_policy_domains))
        for domain in error_dmarc_policy_domains:
            print(Fore.CYAN, "  > %s" % domain)
                     
def print_error(message, new_section=False, fatal=True):
    tag = '[!]' if new_section else ' | '
    print(Fore.RED, f"{tag} ERROR: {message}")
    if fatal:
        sys.exit(1)

def print_warning(message, new_section=False):
    tag = '[-]' if new_section else ' | '
    print(Fore.YELLOW, f"{tag} WARN: {message}")

def print_info(message, new_section=False):
    tag = '[+]' if new_section else ' | '
    print(Fore.LIGHTBLUE_EX, f"{tag} INFO: {message}")

def print_success(message, new_section=False):
    tag = '[+]' if new_section else ' | '
    print(Fore.GREEN, f"{tag} INFO: {message}")
    
def print_verbose(message, new_section=False):
    global args
    tag = '[+]' if new_section else ' | '
    if args.verbose:
        print(Fore.LIGHTBLACK_EX, f"{tag} {message}")
    
if __name__ == "__main__":
    initialize()
