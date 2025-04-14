# Setting Up Automated Bug Bounty Scanner on AWS EC2

This guide provides step-by-step instructions for deploying the enhanced BugBountyScanner with automatic report generation on an AWS EC2 instance.

## Prerequisites

- AWS account with permissions to create and manage EC2 instances
- Basic knowledge of Linux and AWS
- A domain or list of domains to scan

## Step 1: Launch an EC2 Instance

1. Log in to your AWS Management Console
2. Navigate to EC2 and click "Launch Instance"
3. Choose an Ubuntu Server AMI (recommended: Ubuntu Server 22.04 LTS)
4. Select an instance type (recommended: t2.medium or larger for better performance)
5. Configure instance details:
   - Default VPC is fine for basic use
   - Enable public IP assignment
6. Add storage (recommended: 30GB or more)
7. Add necessary tags for your environment
8. Configure security group:
   - Allow SSH (port 22) from your IP
9. Review and launch with your existing key pair or create a new one

## Step 2: Connect to Your Instance

Using SSH:

```bash
ssh -i /path/to/your-key.pem ubuntu@your-instance-public-ip
```

## Step 3: Clone and Set Up the BugBountyScanner

1. Update the system and install Git:

```bash
sudo apt update
sudo apt install -y git
```

2. Clone the BugBountyScanner repository:

```bash
git clone https://github.com/saurabhdubeyy/BugBountyScanner.git
cd BugBountyScanner
```

3. Make the AWS setup script executable and run it:

```bash
chmod +x setup_aws.sh
sudo ./setup_aws.sh
```

If you want to enable Telegram notifications, run with your API key and chat ID:

```bash
sudo ./setup_aws.sh YOUR_TELEGRAM_API_KEY YOUR_TELEGRAM_CHAT_ID
```

The script will:
- Install all required dependencies
- Set up BugBountyScanner
- Create automation scripts for scanning and reporting
- Prepare AWS integration

## Step 4: Configure AWS CLI

To enable S3 integration for storing reports:

```bash
aws configure
```

Enter your AWS access key, secret key, default region, and output format.

## Step 5: Set Up Automated Scanning

1. Create a file with the list of domains you want to scan:

```bash
nano domains.txt
```

Add your target domains (one per line):

```
example.com
target-company.com
```

2. Set up automated scanning with cron jobs:

```bash
./setup_cron.sh domains.txt
```

3. If you want to sync reports to an S3 bucket:

```bash
./setup_cron.sh domains.txt your-s3-bucket-name
```

## Step 6: Run a Test Scan

To ensure everything is working properly, run a test scan:

```bash
./run_bugbounty.sh example.com
```

For a quicker test (useful for testing the setup):

```bash
./run_bugbounty.sh example.com quick
```

## Step 7: Access Your Reports

Reports are stored in the `results` directory, organized by domain and timestamp:

```
results/
└── example.com-2024-04-01_10-30-00/
    ├── example.com/
    │   ├── vulnerability-report-example.com.html  # Main vulnerability report
    │   ├── aquatone_report.html                   # Visual report with screenshots
    │   ├── domains-example.com.txt                # List of discovered subdomains
    │   ├── nuclei-example.com.txt                 # Raw vulnerability findings
    │   └── ...
    └── summary.txt                                # Summary of findings
```

If you've configured S3 integration, reports will also be synced to your S3 bucket daily.

## Security Considerations

1. **IAM Permissions**: Ensure your EC2 instance uses an IAM role with minimal permissions (S3 access only).

2. **Security Groups**: Keep your security group rules tight, only allowing SSH from your IP.

3. **Target Scope**: Only scan domains you have permission to test.

4. **Resource Monitoring**: Keep an eye on your AWS resource usage to avoid unexpected costs.

## Cost Optimization

1. **Instance Scheduling**: Consider using AWS Instance Scheduler to shut down the instance when not in use.

2. **Spot Instances**: For cost savings, you can use EC2 Spot Instances instead of On-Demand instances.

3. **Storage Management**: Implement lifecycle policies on your S3 bucket to archive or delete old reports.

## Troubleshooting

1. **Scan Failures**: Check the logs in the `logs` directory for error messages.

2. **Dependency Issues**: If tools fail to install, try running the setup script again.

3. **Resource Constraints**: If scans are slow or crash, your instance might need more resources. Consider upgrading.

## Advanced Configuration

### Customizing Scanning Options

You can modify the `run_bugbounty.sh` script to adjust scanning parameters, such as:

- Scan depth and thoroughness
- Target specific vulnerabilities
- Custom output formats

### Integrating with Other Services

The modular design allows you to extend the automation:

1. **Email Reports**: Add script sections to email reports when critical vulnerabilities are found.

2. **Slack/Discord Integration**: Send notifications to team collaboration tools.

3. **JIRA Integration**: Automatically create tickets for vulnerabilities that need attention.

## Conclusion

Your automated bug bounty scanning system is now set up on AWS EC2. The system will:

1. Automatically scan your target domains based on the schedule
2. Generate comprehensive vulnerability reports
3. Store the results both locally and in S3 (if configured)
4. Send notifications via Telegram (if configured)

This setup provides a solid foundation for continuous security testing and bug bounty hunting. 