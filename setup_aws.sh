#!/bin/bash
# AWS EC2 Setup Script for BugBountyScanner with Full Automation
# This script sets up an EC2 instance for automated bug bounty hunting

# Make sure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Update system
echo "[*] Updating system packages..."
apt update && apt upgrade -y

# Install required packages
echo "[*] Installing required packages..."
apt install -y python3 python3-pip awscli cron jq unzip curl wget git

# Setup the tool directory
TOOLS_DIR="/opt"
BASE_DIR="$PWD"
mkdir -p "$BASE_DIR/results"

# Clone the BugBountyScanner repository if not already present
if [ ! -d "$BASE_DIR/BugBountyScanner" ]; then
  echo "[*] Cloning BugBountyScanner repository..."
  git clone https://github.com/saurabhdubeyy/BugBountyScanner.git
  cd BugBountyScanner
else
  echo "[*] BugBountyScanner repository already cloned..."
  cd BugBountyScanner
fi

# Setup BugBountyScanner
echo "[*] Running BugBountyScanner setup..."
chmod +x setup.sh
./setup.sh -t "$TOOLS_DIR"

# Copy .env file if it doesn't exist
if [ ! -f ".env" ]; then
  echo "[*] Creating .env file..."
  cp .env.example .env
  # Update .env with Telegram credentials if provided
  if [ ! -z "$1" ] && [ ! -z "$2" ]; then
    echo "[*] Setting up Telegram notifications..."
    sed -i "s/telegram_api_key=.*/telegram_api_key='$1'/" .env
    sed -i "s/telegram_chat_id=.*/telegram_chat_id='$2'/" .env
  else
    # Empty out the Telegram credentials if not provided
    sed -i "s/telegram_api_key=.*/telegram_api_key=''/" .env
    sed -i "s/telegram_chat_id=.*/telegram_chat_id=''/" .env
  fi
fi

# Make the Python report generator executable
chmod +x "$BASE_DIR/BugBountyScanner/utils/generateReport.py"

# Create wrapper script for full automation
echo "[*] Creating automation wrapper script..."
cat > "$BASE_DIR/run_bugbounty.sh" << 'EOF'
#!/bin/bash
# Full automated bug bounty scanner with reporting

# Check if domain is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <domain> [quick]"
  echo "Example: $0 example.com"
  echo "Example with quick mode: $0 example.com quick"
  exit 1
fi

DOMAIN="$1"
BASE_DIR="$(dirname "$(realpath "$0")")"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
RESULT_DIR="$BASE_DIR/results/$DOMAIN-$DATE"
QUICK_FLAG=""

# Check if quick mode is requested
if [ "$2" = "quick" ]; then
  QUICK_FLAG="--quick"
  echo "[*] Running in quick mode..."
fi

# Create results directory
mkdir -p "$RESULT_DIR"

# Run BugBountyScanner
echo "[*] Starting BugBountyScanner on $DOMAIN..."
cd "$BASE_DIR/BugBountyScanner"
./BugBountyScanner.sh -d "$DOMAIN" -o "$RESULT_DIR" -t /opt $QUICK_FLAG -w

# Generate the vulnerability report
echo "[*] Generating vulnerability report..."
if [ -d "$RESULT_DIR/$DOMAIN" ]; then
  python3 "$BASE_DIR/BugBountyScanner/utils/generateReport.py" "$RESULT_DIR/$DOMAIN"
  
  # Create a summary text file for easy reference
  echo "Bug Bounty Report for $DOMAIN" > "$RESULT_DIR/summary.txt"
  echo "Generated on $(date)" >> "$RESULT_DIR/summary.txt"
  echo "--------------------------------------------" >> "$RESULT_DIR/summary.txt"
  
  # Add subdomain count
  if [ -f "$RESULT_DIR/$DOMAIN/domains-$DOMAIN.txt" ]; then
    SUBDOMAIN_COUNT=$(wc -l < "$RESULT_DIR/$DOMAIN/domains-$DOMAIN.txt")
    echo "Subdomains discovered: $SUBDOMAIN_COUNT" >> "$RESULT_DIR/summary.txt"
  fi
  
  # Add vulnerability count
  if [ -f "$RESULT_DIR/$DOMAIN/nuclei-$DOMAIN.txt" ]; then
    VULN_COUNT=$(wc -l < "$RESULT_DIR/$DOMAIN/nuclei-$DOMAIN.txt")
    echo "Vulnerabilities found: $VULN_COUNT" >> "$RESULT_DIR/summary.txt"
    
    # Add critical/high vulnerability info
    CRIT_COUNT=$(grep -c "\[critical\]" "$RESULT_DIR/$DOMAIN/nuclei-$DOMAIN.txt" || echo "0")
    HIGH_COUNT=$(grep -c "\[high\]" "$RESULT_DIR/$DOMAIN/nuclei-$DOMAIN.txt" || echo "0")
    echo "Critical vulnerabilities: $CRIT_COUNT" >> "$RESULT_DIR/summary.txt"
    echo "High vulnerabilities: $HIGH_COUNT" >> "$RESULT_DIR/summary.txt"
  else
    echo "No vulnerabilities found with Nuclei" >> "$RESULT_DIR/summary.txt"
  fi
  
  # Check for special vulnerabilities
  for TYPE in ssti lfi redirect; do
    if [ -f "$RESULT_DIR/$DOMAIN/potential-$TYPE.txt" ] && [ -s "$RESULT_DIR/$DOMAIN/potential-$TYPE.txt" ]; then
      COUNT=$(wc -l < "$RESULT_DIR/$DOMAIN/potential-$TYPE.txt")
      echo "Potential $TYPE vulnerabilities: $COUNT" >> "$RESULT_DIR/summary.txt"
    fi
  done
  
  # Add link to HTML report
  if [ -f "$RESULT_DIR/$DOMAIN/vulnerability-report-$DOMAIN.html" ]; then
    echo "Full report: $RESULT_DIR/$DOMAIN/vulnerability-report-$DOMAIN.html" >> "$RESULT_DIR/summary.txt"
  fi
  
  echo "[+] Scan completed and report generated for $DOMAIN"
  echo "[+] Results saved to $RESULT_DIR"
else
  echo "[-] Error: Scan directory not found at $RESULT_DIR/$DOMAIN"
fi
EOF

# Make the wrapper script executable
chmod +x "$BASE_DIR/run_bugbounty.sh"

# Create AWS setup script
echo "[*] Creating AWS S3 sync script for reports..."
cat > "$BASE_DIR/sync_to_s3.sh" << 'EOF'
#!/bin/bash
# Sync bug bounty reports to Amazon S3

# Check if AWS bucket name is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <s3_bucket_name>"
  echo "Example: $0 my-bug-bounty-reports"
  exit 1
fi

BUCKET_NAME="$1"
BASE_DIR="$(dirname "$(realpath "$0")")"
RESULTS_DIR="$BASE_DIR/results"

# Check if the results directory exists
if [ ! -d "$RESULTS_DIR" ]; then
  echo "[-] Error: Results directory not found at $RESULTS_DIR"
  exit 1
fi

# Sync results to S3
echo "[*] Syncing reports to S3 bucket: $BUCKET_NAME"
aws s3 sync "$RESULTS_DIR" "s3://$BUCKET_NAME/reports/" --exclude "*.log"

echo "[+] Sync completed"
EOF

# Make the S3 sync script executable
chmod +x "$BASE_DIR/sync_to_s3.sh"

# Create a cron job setup script
echo "[*] Creating cron job setup script..."
cat > "$BASE_DIR/setup_cron.sh" << 'EOF'
#!/bin/bash
# Setup cron jobs for automated bug bounty scanning

# Check if domains file is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <domains_file> [s3_bucket_name]"
  echo "Example: $0 domains.txt my-bug-bounty-bucket"
  echo ""
  echo "The domains file should contain one domain per line."
  exit 1
fi

DOMAINS_FILE="$1"
S3_BUCKET="$2"
BASE_DIR="$(dirname "$(realpath "$0")")"

# Check if the domains file exists
if [ ! -f "$DOMAINS_FILE" ]; then
  echo "[-] Error: Domains file not found at $DOMAINS_FILE"
  exit 1
fi

# Create a temporary file for the new crontab
TEMP_CRON=$(mktemp)

# Get existing crontab
crontab -l > "$TEMP_CRON" 2>/dev/null || echo "# Bug Bounty Automated Scans" > "$TEMP_CRON"

# Add header for our section
echo "" >> "$TEMP_CRON"
echo "# Bug Bounty Automated Scans - $(date)" >> "$TEMP_CRON"
echo "# ---------------------------------" >> "$TEMP_CRON"

# Schedule scans for each domain
# Space them out at different times to avoid resource conflicts
COUNT=0
while IFS= read -r domain || [[ -n "$domain" ]]; do
  # Skip empty lines and comments
  if [[ -z "$domain" || "$domain" == \#* ]]; then
    continue
  fi
  
  # Calculate hour and minute (distribute over 24 hours)
  HOUR=$((COUNT % 24))
  MINUTE=$((COUNT * 3 % 60))
  
  # Schedule the scan - run once a week
  DAY_OF_WEEK=$((COUNT % 7))
  echo "$MINUTE $HOUR * * $DAY_OF_WEEK $BASE_DIR/run_bugbounty.sh $domain >> $BASE_DIR/logs/cron_$domain.log 2>&1" >> "$TEMP_CRON"
  
  COUNT=$((COUNT + 1))
done < "$DOMAINS_FILE"

# Add S3 sync job if bucket provided (run daily at 8 AM)
if [ ! -z "$S3_BUCKET" ]; then
  echo "0 8 * * * $BASE_DIR/sync_to_s3.sh $S3_BUCKET >> $BASE_DIR/logs/s3_sync.log 2>&1" >> "$TEMP_CRON"
fi

# Create logs directory
mkdir -p "$BASE_DIR/logs"

# Install the new crontab
crontab "$TEMP_CRON"
rm "$TEMP_CRON"

echo "[+] Cron jobs set up for $(grep -c "run_bugbounty.sh" "$TEMP_CRON") domains"
if [ ! -z "$S3_BUCKET" ]; then
  echo "[+] S3 sync job scheduled to run daily at 8:00 AM"
fi
EOF

# Make the cron setup script executable
chmod +x "$BASE_DIR/setup_cron.sh"

# Create a simple domains example file
echo "[*] Creating example domains file..."
cat > "$BASE_DIR/domains_example.txt" << 'EOF'
# Example domains file for automated scanning
# Add one domain per line, lines starting with # are ignored

example.com
# test.com
# target.org
EOF

echo "[*] Creating setup guide..."
cat > "$BASE_DIR/SETUP_GUIDE.md" << 'EOF'
# AWS EC2 Bug Bounty Scanner Setup Guide

This guide will help you configure the BugBountyScanner for automated vulnerability scanning and reporting.

## Initial Setup

The installation script has already set up the essential components:

1. BugBountyScanner with all dependencies
2. Custom report generation scripts
3. Automation scripts for AWS integration

## Running a Manual Scan

To scan a domain manually and generate a report:

```bash
./run_bugbounty.sh example.com
```

For a faster scan (skipping some time-consuming steps):

```bash
./run_bugbounty.sh example.com quick
```

## Setting Up Automated Scans

1. Edit the `domains_example.txt` file to include the domains you want to scan:

```bash
nano domains_example.txt
```

2. Set up cron jobs to run scans automatically:

```bash
./setup_cron.sh domains_example.txt
```

If you want to sync reports to an S3 bucket, provide the bucket name:

```bash
./setup_cron.sh domains_example.txt my-bug-bounty-reports
```

## AWS S3 Integration

1. Ensure your AWS CLI is configured with the correct credentials:

```bash
aws configure
```

2. Create an S3 bucket for your reports (if not already created):

```bash
aws s3 mb s3://my-bug-bounty-reports
```

3. To manually sync reports to S3:

```bash
./sync_to_s3.sh my-bug-bounty-reports
```

## Telegram Notifications

If you want to enable Telegram notifications:

1. Edit the .env file in the BugBountyScanner directory:

```bash
nano BugBountyScanner/.env
```

2. Update with your Telegram API key and chat ID:

```
toolsDir='/opt'
telegram_api_key='YOUR_API_KEY'
telegram_chat_id='YOUR_CHAT_ID'
```

## Viewing Reports

Reports are stored in the `results` directory, organized by domain and date:

```
results/
├── example.com-2024-04-01_10-30-00/
│   ├── example.com/
│   │   ├── vulnerability-report-example.com.html
│   │   ├── aquatone_report.html
│   │   └── ...
│   └── summary.txt
└── ...
```

Each scan produces a detailed HTML report suitable for submission to bug bounty programs.
EOF

echo "[+] Setup completed successfully!"
echo "[*] You can now run scans with: ./run_bugbounty.sh <domain>"
echo "[*] See SETUP_GUIDE.md for complete instructions." 