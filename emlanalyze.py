import argparse
import email
import hashlib
import requests
from termcolor import colored
import re


VIRUSTOTAL_API_KEY = "VIRUSTOTAL_API_KEY"
def analyze_eml(eml_file):
    try:
        with open(eml_file, 'rb') as file:
            eml_data = file.read()

        # Parse the .eml file
        msg = email.message_from_bytes(eml_data)

        # General Information
        from_address = msg['From']
        reply_to = msg['Reply-To']
        to_addresses = msg['To']
        date = msg['Date']
        subject = msg['Subject']
        return_path = msg['Return-Path']
        message_id = msg['Message-ID']

        # Calculate hash values
        md5_hash = hashlib.md5(eml_data).hexdigest()
        sha1_hash = hashlib.sha1(eml_data).hexdigest()
        sha256_hash = hashlib.sha256(eml_data).hexdigest()


        # Print the results in green
        print(colored("General Information:", "green"))
        print(f"From: {from_address}")
        print(f"Reply To: {reply_to}")
        print(f"To: {to_addresses}")
        print(f"Date: {date}")
        print(f"Subject: {subject}")
        print(colored("Hash values of the .eml file itself:", "green"))
        print(f"MD5: {md5_hash}")
        print(f"SHA1: {sha1_hash}")
        print(f"SHA256: {sha256_hash}")

        # Check email validity and reputation
        email_address = from_address  # You can change this to the appropriate email address in the .eml file
        validate_email(email_address)

                # Basic Security Check
        security_check(from_address, to_addresses, return_path, message_id)

        # Extract and analyze attachments
        extract_and_analyze_attachments(msg)

        # Extract URLs from the body and defang them
        



    except Exception as e:
        print(f"Error: {e}")


def validate_email(email_address):
    try:
        # Check email reputation using emailrep.io API
        emailrep_response = requests.get(f"https://emailrep.io/{email_address}")
        emailrep_data = emailrep_response.json()
        
        if "error" in emailrep_data:
            print(f"Error while checking email reputation: {emailrep_data['error']}")
            return

        if emailrep_data.get("suspicious") or not emailrep_data.get("valid"):
            print("Email is suspicious or not valid (emailrep.io)")
            print("Details: ")
            print(f"- Reputation Score: {emailrep_data.get('reputation', 'N/A')}")
            print(f"- Details: {emailrep_data.get('details', 'N/A')}")
            print(f"- Tags: {emailrep_data.get('tags', 'N/A')}")
            print(colored("WARNING: This email may be suspicious or invalid!", "red"))

        # Diğer işlemler aynı şekilde devam eder

    except Exception as e:
        print(f"Error while validating email: {e}")


def extract_and_defang_urls(msg):
    urls = []
    body = msg.get_payload()

    if body:
        # Extract URLs from the body using a regular expression
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body)

        # Defang the URLs by replacing dots with [dot] and removing hyperlinks
        defanged_urls = []
        for url in urls:
            defanged_url = url.replace('.', '[dot]')
            defanged_urls.append(defanged_url)

        return defanged_urls

    return urls

def security_check(from_address, to_addresses, return_path, message_id):
    print(colored("\n Basic Security Check:", "cyan"))

    if from_address == to_addresses:
        print(colored("  'From' and 'To' fields match","green"))
    else:
        print(colored("  'From' and 'To' fields are not the same","red"))

    if from_address == return_path:
        print(colored("  'From' and 'Return-Path' fields match","green"))
    else:
        print(colored("  'From' and 'Return-Path' fields do not match","red"))

    if message_id:
        print(colored(f"  Message ID found: {message_id}","green"))
    else:
        print(colored("  Message ID not found","red"))

    # Check for mismatches and display a warning
    if (from_address != to_addresses) or (from_address != return_path) or not message_id:
        print(colored("WARNING: Basic security check failed!", "red"))
def extract_and_analyze_attachments(msg):
    attachments = []

    # Extract attachments
    for part in msg.walk():
        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
            attachment = {
                'filename': part.get_filename(),
                'content': part.get_payload(decode=True)
            }
            attachments.append(attachment)

    if attachments:
        print(colored("\n Attachments:", "cyan"))
        for index, attachment in enumerate(attachments, start=1):
            print(colored(f"Attachment {index}:", "green"))
            print(f"  Filename: {attachment['filename']}")
            md5_hash = hashlib.md5(attachment['content']).hexdigest()
            sha1_hash = hashlib.sha1(attachment['content']).hexdigest()
            sha256_hash = hashlib.sha256(attachment['content']).hexdigest()
            print(f"  MD5: {md5_hash}")
            print(f"  SHA1: {sha1_hash}")
            print(f"  SHA256: {sha256_hash}")

            # Analyze attachment with Virustotal
            analyze_attachment_with_virustotal(attachment['content'])

def analyze_attachment_with_virustotal(attachment_content):
    print(colored("\n Virustotal Results","cyan"))
    try:
        files = {'file': attachment_content}
        params = {'apikey': VIRUSTOTAL_API_KEY}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)

        if response.status_code == 200:
            json_response = response.json()
            resource = json_response.get('resource')
            if resource:
                print(f"  Virustotal Analysis (SHA256): {resource}")

                # Get the analysis report with more details
                report_response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                               params={'apikey': VIRUSTOTAL_API_KEY, 'resource': resource})
                report_json = report_response.json()
                if report_json.get('response_code') == 1:
                    # File has been scanned
                    positives = report_json.get('positives', 0)
                    total = report_json.get('total', 0)
                    scans = report_json.get('scans', {})

                    print(f"  Virustotal Analysis Result: {positives} out of {total} engines detected it as malicious")
                    print("  Detailed Scan Results (Top 5):")

                    # Sort and filter the top 5 scan results by detection rate
                    top_5_scans = sorted(scans.items(), key=lambda x: x[1]['detected'], reverse=True)[:5]

                    for antivirus, result in top_5_scans:
                        scan_result = result.get('result', 'N/A')
                        print(f"    {antivirus}: {scan_result}")

                    # Print additional scan results if more than 5 engines detected it as malicious
                    if positives > 5:
                        print(f"  Additional Scan Results ({positives - 5} more engines detected it as malicious):")
                        for antivirus, result in scans.items():
                            if result['detected'] and antivirus not in [av[0] for av in top_5_scans]:
                                scan_result = result.get('result', 'N/A')
                                print(f"    {antivirus}: {scan_result}")

                else:
                    print("  Virustotal Analysis Result: Not available")
            else:
                print("  Virustotal Analysis: Resource not found")
        else:
            print("  Virustotal Analysis: Error while submitting the file for analysis")

    except Exception as e:
        print(f"Error while analyzing attachment with Virustotal: {e}")

def main():
    parser = argparse.ArgumentParser(description='E-mail Analyzer Tool')
    parser.add_argument('eml_file', metavar='eml_file', type=str, help='Path to the .eml file for analysis')
    args = parser.parse_args()

    analyze_eml(args.eml_file)

if __name__ == "__main__":
    main()