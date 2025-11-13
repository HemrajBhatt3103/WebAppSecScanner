#!/usr/bin/env python3
import sys
import re
from datetime import datetime

def sanitize_filename(url):
    """Convert URL to a safe filename"""
    # Remove protocol and special characters
    safe_name = re.sub(r'^https?://', '', url)
    safe_name = re.sub(r'[^a-zA-Z0-9\.]', '_', safe_name)
    # Limit length to avoid filesystem issues
    if len(safe_name) > 50:
        safe_name = safe_name[:50]
    return safe_name

def main():
    # Simple argument parsing without argparse
    format_type = 'pdf'  # Default to PDF instead of HTML
    store_db = False
    
    # Check for format argument
    if '-f' in sys.argv or '--format' in sys.argv:
        try:
            format_index = sys.argv.index('-f') if '-f' in sys.argv else sys.argv.index('--format')
            format_type = sys.argv[format_index + 1]
            if format_type not in ['html', 'pdf', 'json']:
                print("Error: Format must be html, pdf, or json")
                sys.exit(1)
        except (IndexError, ValueError):
            print("Error: Format argument requires a value (html, pdf, or json)")
            sys.exit(1)
    
    # Check for store-db argument
    if '--store-db' in sys.argv:
        store_db = True
    
    # Prompt for URL first, before importing any modules that might cause issues
    target_url = input("Please enter the target URL to scan: ").strip()
    if not target_url:
        print("Error: No target URL provided")
        sys.exit(1)
    
    # Now import the modules after getting the URL
    from scanners.zap_scanner import ZAPScanner
    from scanners.whatweb_scanner import WhatWebScanner
    from report.generator import ReportGenerator
    from storage.mongo_handler import MongoDBHandler
    
    # Generate output filename with timestamp and URL
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = sanitize_filename(target_url)
    output_filename = f"security_scan_{safe_url}_{timestamp}"
    
    print(f"[+] Starting scan for {target_url}")
    print(f"[+] Output file: {output_filename}.{format_type}")
    
    # Run WhatWeb for framework detection
    print("[+] Running framework detection with WhatWeb...")
    whatweb_scanner = WhatWebScanner()
    framework_data = whatweb_scanner.scan(target_url)
    
    # Run OWASP ZAP for vulnerability scanning
        # Run OWASP ZAP for vulnerability scanning
    print("[+] Running vulnerability scan with OWASP ZAP...")
    zap_scanner = ZAPScanner()
    
    # Try scanning - the scanner will handle timeouts gracefully
    vulnerability_data = zap_scanner.scan(target_url)
    
    # Check if we got any results
    if vulnerability_data.get("vulnerabilities"):
        print(f"[+] Found {len(vulnerability_data['vulnerabilities'])} vulnerabilities")
    elif "error" in vulnerability_data:
        print(f"[!] ZAP Scan Issues: {vulnerability_data['error']}")
        print("[+] Continuing with available results...")
    
    # Generate report
    print("[+] Generating report...")
    report_generator = ReportGenerator()
    report_path = report_generator.generate_report(
        target_url, 
        framework_data, 
        vulnerability_data, 
        output_filename, 
        format_type
    )
    
    # Store in MongoDB if requested
    if store_db:
        print("[+] Storing results in MongoDB...")
        db_handler = MongoDBHandler()
        db_handler.store_scan(
            target_url, 
            framework_data, 
            vulnerability_data, 
            report_path
        )
    
    print(f"[+] Scan completed. Report saved to {report_path}")

if __name__ == "__main__":
    main()

