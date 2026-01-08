# Installation Guide

## Prerequisites

### 1. Server Requirements

- **OS**: Ubuntu 22.04 LTS (or compatible Linux)
- **RAM**: 4 GB minimum (8 GB recommended)
- **Disk**: 20 GB SSD minimum
- **Network**: Static IP recommended

### 2. Install Docker

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add user to docker group
sudo usermod -aG docker $USER

# Start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Verify installation
docker --version
docker compose version
```

### 3. Configure Sophos XGS

1. **Enable Syslog**:
   - Go to: System > Administration > Notification > Syslog
   - Add a new server
   - IP: Your VIGILANCE X server IP
   - Port: 514 (UDP) or 1514 (TCP)

2. **Select Log Types**:
   - Web Filter
   - IPS/IDS
   - WAF
   - Authentication
   - Firewall

3. **Enable XML API** (for ban management):
   - Go to: System > Administration > Admin Settings
   - Enable API access
   - Note the API port (default: 4444)

## Installation Steps

### Step 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/kr1s57/vigilanceX-SOC.git
cd vigilanceX-SOC
```

### Step 2: Configure Environment

```bash
# Create configuration file
cp deploy/config.template deploy/.env

# Edit configuration
nano deploy/.env
```

**Required Settings:**

```bash
# Database passwords (generate secure passwords)
CLICKHOUSE_PASSWORD=your_secure_password_here
REDIS_PASSWORD=another_secure_password

# JWT Secret (generate with: openssl rand -hex 32)
JWT_SECRET=your_32_char_minimum_secret_here

# Sophos XGS
SOPHOS_HOST=10.x.x.x          # Sophos IP address
SOPHOS_PORT=4444              # API port
SOPHOS_USER=admin             # API username
SOPHOS_PASSWORD=sophos_pass   # API password

# License (contact support@vigilancex.io)
LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
```

### Step 3: SSH Key (Optional - ModSec)

If using ModSecurity log correlation:

```bash
# Generate SSH key
ssh-keygen -t rsa -b 4096 -f deploy/ssh/id_rsa_xgs -N ""

# Copy public key to Sophos XGS
ssh-copy-id -i deploy/ssh/id_rsa_xgs.pub admin@SOPHOS_IP

# Set permissions
chmod 600 deploy/ssh/id_rsa_xgs
```

### Step 4: Install

```bash
# Run installation
./vigilance.sh install
```

The script will:
1. Pull Docker images from GitHub Container Registry
2. Create Docker volumes for data persistence
3. Start all services
4. Initialize the database

### Step 5: Access Dashboard

1. Open browser: `https://your-server-ip`
2. Accept the self-signed certificate (or install your own)
3. Login with default credentials:
   - **Username**: admin
   - **Password**: VigilanceX2024!

### Step 6: Activate License

1. Go to: Settings > License
2. Enter your license key
3. Click "Activate"

## SSL Certificate Setup

### Option A: Self-Signed (Default)

The default installation uses a self-signed certificate. For production, replace with a valid certificate.

### Option B: Let's Encrypt

```bash
# Install certbot
sudo apt install certbot

# Generate certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem config/nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem config/nginx/ssl/

# Restart nginx
./vigilance.sh restart
```

### Option C: Custom Certificate

```bash
# Copy your certificates
cp your-certificate.crt config/nginx/ssl/vigilance.crt
cp your-private-key.key config/nginx/ssl/vigilance.key

# Set permissions
chmod 600 config/nginx/ssl/*

# Restart nginx
./vigilance.sh restart
```

## Verification

### Check Services

```bash
./vigilance.sh status
```

All services should show "Up" status.

### Check Logs

```bash
# All services
./vigilance.sh logs

# Specific service
./vigilance.sh logs backend
```

### Verify Syslog Reception

1. Check Vector is receiving logs:
```bash
./vigilance.sh logs vector
```

2. Check events in dashboard:
   - Go to: WAF Explorer
   - You should see events from your Sophos XGS

## Troubleshooting

### Services Not Starting

```bash
# Check Docker logs
docker logs vigilance_backend
docker logs vigilance_clickhouse

# Check disk space
df -h

# Check memory
free -h
```

### No Events in Dashboard

1. Verify Sophos Syslog is configured correctly
2. Check firewall rules (port 514/1514)
3. Check Vector logs: `./vigilance.sh logs vector`

### License Activation Failed

1. Check internet connectivity
2. Verify license key is correct
3. Check if `/etc/machine-id` exists
4. Contact support@vigilancex.io

## Next Steps

- [Configuration Reference](Configuration.md)
- [Security Hardening](Security-Hardening.md)
- [Administration Guide](Administration.md)
