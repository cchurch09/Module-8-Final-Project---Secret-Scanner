#Cailli Church
#SDEV 245 MOD 8 Secret Scanner

import os
import re
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s")

#regextokens
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",}

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            for line_num, line in enumerate(file, start=1):
                #Use regex to detect common secret patterns
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        findings.append({
                            "type": secret_type,
                            "file": filepath,
                            "line": line_num,
                            "match": match.group()})
    except Exception as e:
        logging.error(f"Could not scan file {filepath}: {e}")
    return findings


def scan_directory(directory):
    all_findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            logging.info(f"Scanning file: {filepath}")
            findings = scan_file(filepath)
            all_findings.extend(findings)
    return all_findings

#Output a report of findings (filename, line number, matched string)
def print_report(findings):
    print("\n========== SECRET SCAN REPORT ==========\n")
    if not findings:
        print("No potential secrets found.")
        return
    for finding in findings:
        print(f"[!] {finding['type']} Detected")
        print(f"    File : {finding['file']}")
        print(f"    Line : {finding['line']}")
        print(f"    Match: {finding['match']}")
        print("-" * 50)
    print(f"\nTotal Findings: {len(findings)}")


def main():
    #Accept a directory path or file as input
    parser = argparse.ArgumentParser(
        description="Python CLI Secret Scanner")
    parser.add_argument(
        "path",
        help="Path to file or directory to scan" )
    args = parser.parse_args()
    target_path = args.path
    logging.info(f"Starting scan on: {target_path}")
    findings = []
    if os.path.isfile(target_path):
        findings = scan_file(target_path)
    elif os.path.isdir(target_path):
        findings = scan_directory(target_path)
    else:
        logging.error("Invalid file or directory path.")
        return
    print_report(findings)


if __name__ == "__main__":
    main()