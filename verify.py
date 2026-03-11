import re
import dns.resolver
import smtplib
import socket
import time
from typing import Tuple

def verify_email(email: str) -> Tuple[bool, str]:
    """
    Improved email verification with reduced false negatives.
    """
    # 1. Basic syntax check
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email syntax"
    
    domain = email.split('@')[1].lower()
    
    # Special handling for known providers
    known_providers = {
        'gmail.com': (True, "Gmail provider"),
        'googlemail.com': (True, "Gmail provider"),
        'outlook.com': (True, "Outlook provider"),
        'hotmail.com': (True, "Outlook provider"),
        'yahoo.com': (True, "Yahoo provider"),
        'ymail.com': (True, "Yahoo provider"),
        'icloud.com': (True, "iCloud provider"),
        'protonmail.com': (True, "ProtonMail provider"),
        'mail.com': (True, "Mail.com provider")
    }
    
    if domain in known_providers:
        return known_providers[domain]
    
    try:
        # 2. Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if not mx_records:
                return False, "No MX records found"
            mx_record = str(mx_records[0].exchange)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False, "Domain does not exist or has no MX records"
        
        # 3. Conservative SMTP check
        try:
            with smtplib.SMTP(mx_record, timeout=10) as server:
                server.set_debuglevel(0)
                server.helo(server.local_hostname)
                return True, "Server responded positively"
                
        except smtplib.SMTPConnectError:
            return False, "Could not connect to mail server"
        except (smtplib.SMTPServerDisconnected, socket.timeout, socket.gaierror):
            return True, "Temporary failure - assuming valid"
            
    except Exception as e:
        return True, f"Verification error - assuming valid: {str(e)}"

def process_email_list(input_file: str, clean_file: str, bounced_file: str, delay: float = 1.0):
    """
    Process email list with proper file saving.
    """
    try:
        # Read all emails first to count total
        with open(input_file, 'r') as f:
            emails = [line.strip() for line in f if line.strip()]
        total_emails = len(emails)
        
        # Open output files in write mode (this will create them if they don't exist)
        with open(clean_file, 'w') as clean_out, open(bounced_file, 'w') as bounced_out:
            # Write headers
            clean_out.write("Email\tStatus\tDetails\n")
            bounced_out.write("Email\tStatus\tDetails\n")
            
            valid = invalid = 0
            
            for i, email in enumerate(emails, 1):
                is_valid, message = verify_email(email)
                
                if is_valid:
                    valid += 1
                    clean_out.write(f"{email}\tValid\t{message}\n")
                    print(f"✅ [{i}/{total_emails}] {email} (Valid: {message})")
                else:
                    invalid += 1
                    bounced_out.write(f"{email}\tInvalid\t{message}\n")
                    print(f"❌ [{i}/{total_emails}] {email} (Invalid: {message})")
                
                # Flush writes to ensure data is saved
                clean_out.flush()
                bounced_out.flush()
                
                # Add delay except for last email
                if i < total_emails:
                    time.sleep(delay)
            
            print(f"\nProcessing complete!")
            print(f"Total emails processed: {total_emails}")
            print(f"Valid emails: {valid} (saved to {clean_file})")
            print(f"Invalid emails: {invalid} (saved to {bounced_file})")
    
    except FileNotFoundError:
        print(f"Error: The input file '{input_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    # Configuration - change these as needed
    INPUT_FILE = "list.txt"        # Input file with one email per line
    CLEAN_FILE = "clean.txt"      # Output file for valid emails
    BOUNCED_FILE = "bounced.txt"  # Output file for invalid emails
    DELAY = 1.0                         # Seconds between checks
    
    print("Starting email verification process...")
    print(f"Reading emails from: {INPUT_FILE}")
    print(f"Valid emails will be saved to: {CLEAN_FILE}")
    print(f"Invalid emails will be saved to: {BOUNCED_FILE}")
    print(f"Delay between checks: {DELAY} seconds\n")
    
    process_email_list(INPUT_FILE, CLEAN_FILE, BOUNCED_FILE, DELAY)
