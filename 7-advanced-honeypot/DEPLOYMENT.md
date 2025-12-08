# AWS Deployment Guide - Advanced Honeypot

Deploy your honeypot to AWS EC2 to collect real-world attack data.

## Architecture Overview

```
Your Kali VM (Lab)          AWS EC2 (Production)
    ↓                              ↓
honeypot.py              honeypot.py (exposed)
(127.0.0.1 only)         (0.0.0.0, public IP)
    ↓                              ↓
Test attacks         Real attackers find it
    ↓                              ↓
Small dataset        Large threat dataset
(resume-building)    (portfolio showcase)
```

## Prerequisites

- AWS account with EC2 credits
- SSH key pair configured
- Basic Linux command line knowledge
- Honeypot tested locally first

## Phase 1: AWS EC2 Setup (15 minutes)

### Step 1: Launch EC2 Instance

1. Go to AWS Console → EC2 → Instances
2. Click "Launch Instances"
3. Select **Ubuntu 22.04 LTS** (free tier eligible)
4. Instance type: **t2.micro** (free tier)
5. Storage: **20 GB** (default)
6. Security Group (create new):
   - Allow SSH (22) from your IP only
   - Allow ALL TCP (1-65535) from anywhere (for honeypot)
   - Allow ICMP from anywhere (for ping/scans)

```
Inbound Rules:
┌─────────┬───────────┬──────────────┬──────────┐
│ Type    │ Protocol  │ Port Range   │ Source   │
├─────────┼───────────┼──────────────┼──────────┤
│ SSH     │ TCP       │ 22           │ Your IP  │
│ ALL TCP │ TCP       │ 1-65535      │ 0.0.0.0  │
│ ICMP    │ ICMP      │ All          │ 0.0.0.0  │
└─────────┴───────────┴──────────────┴──────────┘
```

7. Key pair: Create or use existing
8. Launch instance

### Step 2: Connect to Instance

```bash
# Get public IP from AWS Console
# SSH into instance
ssh -i your-key.pem ubuntu@your-public-ip.compute.amazonaws.com

# Verify connection
ubuntu@ip-172-31-0-1:~$ 
```

### Step 3: Install Dependencies

```bash
# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install required tools
sudo apt-get install -y python3 nmap tcpdump git

# Verify installations
python3 --version
nmap --version
```

## Phase 2: Deploy Honeypot (10 minutes)

### Step 1: Copy Project to EC2

Option A: Git clone
```bash
# On EC2 instance
cd ~
git clone https://github.com/your-username/infosec-beginner-projects.git
cd infosec-beginner-projects/7-advanced-honeypot
```

Option B: SCP files
```bash
# From your local machine
scp -i your-key.pem -r 7-advanced-honeypot ubuntu@your-public-ip:~

# On EC2
cd ~/7-advanced-honeypot
```

### Step 2: Configure for AWS

Edit `honeypot.py` to expose to internet:

```python
# BEFORE (localhost only):
honeypot = AdvancedHoneypot(
    ports=[22, 23, 80, 443, 3306, 8080],
    bind_address='127.0.0.1'  # Local only
)

# AFTER (public exposure):
honeypot = AdvancedHoneypot(
    ports=[22, 23, 80, 443, 3306, 8080],
    bind_address='0.0.0.0'    # All interfaces
)
```

### Step 3: Start Honeypot

```bash
# Run honeypot (foreground)
python3 honeypot.py

# Or background with logging
nohup python3 honeypot.py > honeypot.log 2>&1 &

# Verify it's running
sudo netstat -tlnp | grep python
```

### Step 4: Verify Honeypot is Accessible

From your local machine:
```bash
# Test connectivity
nmap -sT -p 22,23,80,443 your-public-ip.compute.amazonaws.com

# Expected output:
# 22/tcp   open   ssh
# 23/tcp   open   telnet
# 80/tcp   open   http
# 443/tcp  open   https
```

## Phase 3: Monitoring & Analysis (Ongoing)

### Weekly Analysis

```bash
# SSH to instance
ssh -i your-key.pem ubuntu@your-public-ip.compute.amazonaws.com

# Run analysis
python3 analyzer.py

# View report
cat honeypot_threat_report.txt
```

### Database Backup

```bash
# Download database to local machine
scp -i your-key.pem ubuntu@your-public-ip:~/7-advanced-honeypot/honeypot.db ./honeypot_backup_$(date +%Y%m%d).db

# Keep local backups of threat intelligence
```

### Monitor Disk Usage

```bash
# Check database size
du -sh honeypot.db

# If it gets too large (>1GB), archive and rotate:
sqlite3 honeypot.db "SELECT COUNT(*) FROM attack_attempts;"

# Archive old data
sqlite3 honeypot.db "SELECT * FROM attack_attempts WHERE timestamp < datetime('now', '-30 days');" > old_attacks.csv
```

## Advanced Configuration

### Use t2.micro Forever (Free Tier)

```bash
# Install CloudWatch monitoring
sudo apt-get install -y awscli

# Setup billing alerts in AWS Console
# (Prevent unexpected costs)
```

### Increase Port Range

Edit honeypot.py to monitor more ports:

```python
# Monitor common services + web services
ports=[
    22, 23,      # SSH, Telnet
    80, 443,     # HTTP, HTTPS
    3306, 5432,  # MySQL, PostgreSQL
    3389,        # RDP
    8080, 8443,  # Alt HTTP
    9200, 9300,  # Elasticsearch
    27017,       # MongoDB
    6379,        # Redis
]
```

### Persistent Logs

Create systemd service:

```bash
# Create service file
sudo nano /etc/systemd/system/honeypot.service

# Paste:
[Unit]
Description=Advanced Honeypot with Deception Technology
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/7-advanced-honeypot
ExecStart=/usr/bin/python3 /home/ubuntu/7-advanced-honeypot/honeypot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl enable honeypot
sudo systemctl start honeypot

# View status
sudo systemctl status honeypot

# Logs
journalctl -u honeypot -f
```

### CloudWatch Integration

Send metrics to AWS CloudWatch:

```python
# Add to honeypot.py
import boto3

cloudwatch = boto3.client('cloudwatch')

# Every hour, report metrics
cloudwatch.put_metric_data(
    Namespace='Honeypot',
    MetricData=[
        {
            'MetricName': 'AttackCount',
            'Value': attack_count,
            'Unit': 'Count'
        },
        {
            'MetricName': 'UniqueAttackers',
            'Value': unique_ips,
            'Unit': 'Count'
        }
    ]
)
```

## Cost Estimation

| Component | Cost (Free Tier) | Cost (Beyond) |
|-----------|------------------|---------------|
| EC2 t2.micro | $0 (750 hours/month) | $0.0116/hour |
| Data transfer | $0 (15GB/month) | $0.09/GB |
| Storage (20GB) | $0 | $0.10/GB/month |
| **Monthly** | **~$0-5** | **~$10-50** |

**Cost Control:**
- Set up billing alerts ($5, $10, $20)
- Use Free Tier resources only
- Monitor data transfer
- Delete instance when not needed

## Security Best Practices

### 1. Limit SSH Access
```bash
# Edit security group
# SSH: Allow only YOUR IP (not 0.0.0.0)

# Change SSH port (optional)
# Edit /etc/ssh/sshd_config: Port 2222
sudo systemctl restart ssh
```

### 2. Monitor Access Logs
```bash
# Check who's accessing
cat /var/log/auth.log | tail -20

# Set up fail2ban to block brute force on SSH
sudo apt-get install fail2ban
```

### 3. Regular Updates
```bash
# Schedule weekly updates
0 2 * * 0 sudo apt-get update && sudo apt-get upgrade -y
```

### 4. Backup Data
```bash
# Weekly backup of threat intelligence
0 3 * * 1 scp -i key.pem ubuntu@ip:~/honeypot.db ~/backups/
```

## Troubleshooting

### Q: Instance unreachable
**A:**
```bash
# Check security group
# Verify SSH (22) allows your IP
# Verify port 80/443 allows 0.0.0.0 (for honeypot)

# Check instance status in AWS Console
# Reboot if needed
```

### Q: Honeypot not receiving attacks
**A:**
```bash
# Verify public IP is accessible
nmap -sT -p 80 your-public-ip.compute.amazonaws.com

# Check if honeypot is running
ps aux | grep honeypot

# Monitor network
sudo tcpdump -i eth0 -n 'dst port 80' | head -20
```

### Q: Database growing too fast
**A:**
```bash
# Check growth rate
du -sh honeypot.db

# Archive old data
sqlite3 honeypot.db "DELETE FROM attack_attempts WHERE timestamp < datetime('now', '-90 days');"

# Vacuum database
sqlite3 honeypot.db "VACUUM;"
```

### Q: High AWS charges
**A:**
```bash
# Check what's using resources
sudo top -b -n 1 | head -20

# Check data transfer
# AWS Console → CloudWatch → Data transfer metrics

# Reduce ports if scanning is excessive
# Consider DDoS mitigation (AWS Shield)
```

## Resume Presentation

After 2-4 weeks on AWS:

> "Deployed an advanced honeypot to AWS EC2 that:
> - Collected 50,000+ attack attempts from attackers worldwide
> - Identified attack origins across 87 countries
> - Detected 28 distinct attack tools (Shodan, Metasploit, custom scripts)
> - Captured sophisticated multi-stage attacks with deception engagement
> - Generated threat intelligence reports analyzed for attack patterns and TTPs
> - Demonstrated real-time security monitoring and threat attribution capabilities"

### Metrics to Showcase

1. **Total Attacks**: X,000+
2. **Unique Attackers**: X countries
3. **Attack Types**: X distinct techniques
4. **Deception Success**: X% of attackers triggered traps
5. **Tool Detection Accuracy**: X%
6. **Fastest Attack**: X seconds from first probe to exploitation

## Next Steps

### Immediate (Week 1-2)
- [ ] Instance deployed and accessible
- [ ] Honeypot running and receiving attacks
- [ ] Database growing with real data
- [ ] First threat report generated

### Short-term (Week 2-4)
- [ ] Weekly threat intelligence reports
- [ ] Attack pattern analysis
- [ ] Tool detection accuracy measured
- [ ] Deception trap effectiveness analyzed

### Long-term (After 4 weeks)
- [ ] Portfolio presentation prepared
- [ ] Threat intelligence reports compiled
- [ ] AWS deployment documented
- [ ] GitHub updated with real-world data

### Advanced Options
1. **Scale up**: Deploy multiple honeypots on different networks
2. **Integrate**: Connect to SIEM (Splunk, ELK)
3. **Automate**: Trigger alerts on deception engagement
4. **Analyze**: Build machine learning models on attack data
5. **Share**: Publish anonymized threat intelligence reports

## Cleanup (If Needed)

```bash
# Stop honeypot
sudo systemctl stop honeypot

# Backup data one final time
scp -i your-key.pem ubuntu@your-public-ip:~/honeypot.db ./final_backup.db

# Terminate instance in AWS Console
# (Stops charges immediately)
```

## References

- AWS EC2 Free Tier: https://aws.amazon.com/ec2/
- AWS Security Groups: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
- AWS Pricing Calculator: https://calculator.aws/
- Honeypot Best Practices: https://www.honeypotproject.org/
- Threat Intelligence Standards: https://oasis-open.github.io/cti-documentation/

## Support

If you get stuck:
1. Check honeypot.log for errors
2. Review AWS Console for instance status
3. Test locally first before AWS
4. Verify security group rules
5. Check disk space and database integrity

Happy honeypotting! 🍯
