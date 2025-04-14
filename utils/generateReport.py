#!/usr/bin/env python3
# Comprehensive Vulnerability Report Generator for BugBountyScanner
# This script analyzes the output of BugBountyScanner and generates a professional report

import os
import sys
import json
import datetime
import argparse
from pathlib import Path

# Define the severity levels and their colors
SEVERITY_COLORS = {
    "critical": "darkred",
    "high": "red",
    "medium": "orange",
    "low": "blue",
    "info": "gray"
}

def get_domain_name(domain_dir):
    """Extract domain name from directory path"""
    return os.path.basename(domain_dir)

def scan_nuclei_results(domain_dir):
    """Parse Nuclei output for vulnerabilities"""
    nuclei_file = os.path.join(domain_dir, f"nuclei-{get_domain_name(domain_dir)}.txt")
    vulnerabilities = []
    
    if os.path.exists(nuclei_file):
        with open(nuclei_file, 'r') as f:
            for line in f:
                if '[' in line and ']' in line:
                    try:
                        # Parse the Nuclei output format
                        parts = line.strip().split()
                        severity = None
                        name = None
                        url = None
                        
                        for i, part in enumerate(parts):
                            if part.startswith('[') and part.endswith(']'):
                                if part.lower() in ['[critical]', '[high]', '[medium]', '[low]', '[info]']:
                                    severity = part.lower().strip('[]')
                            if "://" in part:
                                url = part
                        
                        # Extract vulnerability name (usually after the severity)
                        if severity:
                            idx = line.lower().find(f'[{severity}]')
                            if idx > -1:
                                name_start = idx + len(f'[{severity}]')
                                name_end = line.find('[', name_start + 1) if '[' in line[name_start:] else len(line)
                                name = line[name_start:name_end].strip()
                        
                        if severity and url:
                            vulnerabilities.append({
                                "severity": severity,
                                "name": name or "Unknown Vulnerability",
                                "url": url,
                                "description": line.strip()
                            })
                    except Exception as e:
                        print(f"Error parsing line: {line} - {e}")
    
    return vulnerabilities

def scan_potential_vulnerabilities(domain_dir):
    """Scan for potential vulnerabilities identified by specialized tools"""
    potential_vulns = []
    domain = get_domain_name(domain_dir)
    
    # Check for SSTI (Server-Side Template Injection)
    ssti_file = os.path.join(domain_dir, "potential-ssti.txt")
    if os.path.exists(ssti_file) and os.path.getsize(ssti_file) > 0:
        with open(ssti_file, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    potential_vulns.append({
                        "severity": "high",
                        "name": "Server-Side Template Injection",
                        "url": url,
                        "description": "Potential SSTI vulnerability detected"
                    })
    
    # Check for LFI (Local File Inclusion)
    lfi_file = os.path.join(domain_dir, "potential-lfi.txt")
    if os.path.exists(lfi_file) and os.path.getsize(lfi_file) > 0:
        with open(lfi_file, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    potential_vulns.append({
                        "severity": "high",
                        "name": "Local File Inclusion",
                        "url": url,
                        "description": "Potential LFI vulnerability detected"
                    })
    
    # Check for Open Redirect
    redirect_file = os.path.join(domain_dir, "potential-redirect.txt")
    if os.path.exists(redirect_file) and os.path.getsize(redirect_file) > 0:
        with open(redirect_file, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    potential_vulns.append({
                        "severity": "medium",
                        "name": "Open Redirect",
                        "url": url,
                        "description": "Potential Open Redirect vulnerability detected"
                    })
    
    return potential_vulns

def check_subdomain_takeover(domain_dir):
    """Check for subdomain takeover vulnerabilities"""
    takeovers = []
    domain = get_domain_name(domain_dir)
    
    subjack_file = os.path.join(domain_dir, f"subjack-{domain}.txt")
    if os.path.exists(subjack_file) and os.path.getsize(subjack_file) > 0:
        with open(subjack_file, 'r') as f:
            for line in f:
                if "[Vulnerable]" in line:
                    parts = line.strip().split(" - ")
                    if len(parts) >= 2:
                        takeovers.append({
                            "severity": "critical",
                            "name": "Subdomain Takeover",
                            "url": parts[0],
                            "description": f"Vulnerable to subdomain takeover: {line.strip()}"
                        })
    
    return takeovers

def get_domain_statistics(domain_dir):
    """Get statistics about the scanned domain"""
    domain = get_domain_name(domain_dir)
    stats = {
        "domain": domain,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "subdomains": 0,
        "live_endpoints": 0,
        "ip_addresses": 0,
        "ports_open": 0
    }
    
    # Count subdomains
    subdomain_file = os.path.join(domain_dir, f"domains-{domain}.txt")
    if os.path.exists(subdomain_file):
        with open(subdomain_file, 'r') as f:
            stats["subdomains"] = sum(1 for _ in f)
    
    # Count live endpoints
    live_domains_file = os.path.join(domain_dir, f"livedomains-{domain}.txt")
    if os.path.exists(live_domains_file):
        with open(live_domains_file, 'r') as f:
            stats["live_endpoints"] = sum(1 for _ in f)
    
    # Count IP addresses
    ip_file = os.path.join(domain_dir, f"ip-addresses-{domain}.txt")
    if os.path.exists(ip_file):
        with open(ip_file, 'r') as f:
            stats["ip_addresses"] = sum(1 for _ in f)
    
    # Count open ports if nmap results exist
    nmap_file = os.path.join(domain_dir, "nmap/nmap-tcp.gnmap")
    if os.path.exists(nmap_file):
        with open(nmap_file, 'r') as f:
            for line in f:
                if "Ports:" in line:
                    # Count open ports in the Nmap output
                    parts = line.split("Ports: ")[1].split(", ")
                    open_ports = [p for p in parts if "/open/" in p]
                    stats["ports_open"] += len(open_ports)
    
    return stats

def generate_html_report(domain_dir, vulnerabilities, domain_stats):
    """Generate a comprehensive HTML report"""
    domain = get_domain_name(domain_dir)
    output_file = os.path.join(domain_dir, f"vulnerability-report-{domain}.html")
    
    # Count vulnerabilities by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0, 
        "low": 0,
        "info": 0
    }
    
    for vuln in vulnerabilities:
        if vuln["severity"] in severity_counts:
            severity_counts[vuln["severity"]] += 1
    
    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {domain}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .report-header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        .report-date {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .stats-container {{
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin: 20px 0;
            gap: 10px;
        }}
        .stat-box {{
            flex: 1;
            min-width: 150px;
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }}
        .stat-label {{
            font-size: 14px;
            color: #7f8c8d;
        }}
        .severity-summary {{
            margin: 20px 0;
        }}
        .severity-bar {{
            display: flex;
            height: 40px;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .severity-critical {{ background-color: darkred; }}
        .severity-high {{ background-color: red; }}
        .severity-medium {{ background-color: orange; }}
        .severity-low {{ background-color: blue; }}
        .severity-info {{ background-color: gray; }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .vuln-table th, .vuln-table td {{
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        .vuln-table th {{
            background-color: #f2f2f2;
        }}
        .vuln-row-critical {{ background-color: rgba(139, 0, 0, 0.1); }}
        .vuln-row-high {{ background-color: rgba(255, 0, 0, 0.1); }}
        .vuln-row-medium {{ background-color: rgba(255, 165, 0, 0.1); }}
        .vuln-row-low {{ background-color: rgba(0, 0, 255, 0.1); }}
        .vuln-row-info {{ background-color: rgba(128, 128, 128, 0.1); }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
        .severity-indicator {{
            padding: 3px 6px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }}
        .no-vulns-msg {{
            text-align: center;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 5px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>Bug Bounty Vulnerability Report</h1>
        <h2>{domain}</h2>
        <p class="report-date">Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report provides a comprehensive analysis of the security vulnerabilities found in the <strong>{domain}</strong> domain. 
       The automated scanning has identified a total of <strong>{len(vulnerabilities)}</strong> vulnerabilities of varying severity levels.</p>
    
    <div class="stats-container">
        <div class="stat-box">
            <div class="stat-value">{domain_stats['subdomains']}</div>
            <div class="stat-label">Subdomains</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{domain_stats['live_endpoints']}</div>
            <div class="stat-label">Live Endpoints</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{domain_stats['ip_addresses']}</div>
            <div class="stat-label">IP Addresses</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{domain_stats['ports_open']}</div>
            <div class="stat-label">Open Ports</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{len(vulnerabilities)}</div>
            <div class="stat-label">Total Vulnerabilities</div>
        </div>
    </div>
    
    <div class="severity-summary">
        <h3>Vulnerability Severity Distribution</h3>
        <div class="severity-bar">
            <div class="severity-critical" style="width: {max(severity_counts['critical']/max(sum(severity_counts.values()), 1)*100, 0) if severity_counts['critical'] > 0 else 0}%;" title="Critical: {severity_counts['critical']}"></div>
            <div class="severity-high" style="width: {max(severity_counts['high']/max(sum(severity_counts.values()), 1)*100, 0) if severity_counts['high'] > 0 else 0}%;" title="High: {severity_counts['high']}"></div>
            <div class="severity-medium" style="width: {max(severity_counts['medium']/max(sum(severity_counts.values()), 1)*100, 0) if severity_counts['medium'] > 0 else 0}%;" title="Medium: {severity_counts['medium']}"></div>
            <div class="severity-low" style="width: {max(severity_counts['low']/max(sum(severity_counts.values()), 1)*100, 0) if severity_counts['low'] > 0 else 0}%;" title="Low: {severity_counts['low']}"></div>
            <div class="severity-info" style="width: {max(severity_counts['info']/max(sum(severity_counts.values()), 1)*100, 0) if severity_counts['info'] > 0 else 0}%;" title="Info: {severity_counts['info']}"></div>
        </div>
        <div>
            <span><strong>Critical:</strong> {severity_counts['critical']} | </span>
            <span><strong>High:</strong> {severity_counts['high']} | </span>
            <span><strong>Medium:</strong> {severity_counts['medium']} | </span>
            <span><strong>Low:</strong> {severity_counts['low']} | </span>
            <span><strong>Info:</strong> {severity_counts['info']}</span>
        </div>
    </div>
    
    <h2>Detailed Vulnerability Analysis</h2>
"""
    
    # Create vulnerability section by severity
    if vulnerabilities:
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_vulns = [v for v in vulnerabilities if v["severity"] == severity]
            if severity_vulns:
                html_content += f"""
    <h3>{severity.capitalize()} Severity Vulnerabilities ({len(severity_vulns)})</h3>
    <table class="vuln-table">
        <thead>
            <tr>
                <th>#</th>
                <th>Vulnerability</th>
                <th>URL</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
"""
                for i, vuln in enumerate(severity_vulns):
                    html_content += f"""
            <tr class="vuln-row-{severity}">
                <td>{i+1}</td>
                <td>{vuln["name"]}</td>
                <td><a href="{vuln["url"]}" target="_blank">{vuln["url"]}</a></td>
                <td>{vuln["description"]}</td>
            </tr>"""
                html_content += """
        </tbody>
    </table>
"""
    else:
        html_content += """
    <div class="no-vulns-msg">
        <p>No vulnerabilities were found during this scan. This may indicate a well-secured environment or limited scan coverage.</p>
    </div>
"""
    
    # Additional sections
    html_content += f"""
    <h2>Screenshots and Visual Evidence</h2>
    <p>Please refer to the <a href="aquatone_report.html">Aquatone Report</a> for visual evidence of the identified endpoints.</p>
    
    <h2>Methodology</h2>
    <p>This automated security assessment was conducted using BugBountyScanner, which includes the following tools:</p>
    <ul>
        <li><strong>Amass:</strong> For subdomain enumeration</li>
        <li><strong>HTTPX:</strong> For finding live web services</li>
        <li><strong>Nuclei:</strong> For vulnerability scanning</li>
        <li><strong>SubJack:</strong> For subdomain takeover detection</li>
        <li><strong>Aquatone:</strong> For visual reconnaissance</li>
        <li><strong>Custom scanners:</strong> For detecting SSTI, LFI, and open redirect vulnerabilities</li>
    </ul>
    
    <h2>Recommendations</h2>
    <p>Based on the findings of this report, we recommend the following actions:</p>
    <ul>
        <li>Address all Critical and High severity vulnerabilities immediately</li>
        <li>Review Medium severity issues as part of your security program</li>
        <li>Consider Low severity issues for future security improvements</li>
        <li>Implement a regular security testing program</li>
    </ul>
    
    <div class="footer">
        <p>Generated by BugBountyAutomation | © {datetime.datetime.now().year}</p>
    </div>
</body>
</html>
"""
    
    # Write the report to a file
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    return output_file

def main():
    parser = argparse.ArgumentParser(description='Generate vulnerability reports from BugBountyScanner output')
    parser.add_argument('domain_dir', help='Path to the domain directory containing scan results')
    args = parser.parse_args()
    
    domain_dir = args.domain_dir
    if not os.path.isdir(domain_dir):
        print(f"Error: {domain_dir} is not a valid directory")
        sys.exit(1)
    
    print(f"Generating report for {get_domain_name(domain_dir)}...")
    
    # Collect all vulnerabilities
    nuclei_vulns = scan_nuclei_results(domain_dir)
    potential_vulns = scan_potential_vulnerabilities(domain_dir)
    takeover_vulns = check_subdomain_takeover(domain_dir)
    
    all_vulnerabilities = nuclei_vulns + potential_vulns + takeover_vulns
    
    # Sort vulnerabilities by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 999))
    
    # Get domain statistics
    domain_stats = get_domain_statistics(domain_dir)
    
    # Generate HTML report
    report_file = generate_html_report(domain_dir, all_vulnerabilities, domain_stats)
    
    print(f"Report generated: {report_file}")

if __name__ == "__main__":
    main() 