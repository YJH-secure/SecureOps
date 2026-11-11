# SecureOps SSH-01 Deployment Guide

## 1. Purpose

SSH-01 checks the effective PermitRootLogin setting.

The collector runs through a dedicated secureops-scan
account with limited sudo permissions.

## 2. Requirements

- Ubuntu or Rocky Linux with OpenSSH Server
- Python 3 and sudo
- Dedicated secureops-scan account
- Verified SSH public-key authentication
- Administrator approval before deployment

## 3. Configuration

Use secureops-ssh01-read.example as the deployment template.

Before installation, replace:

- REPLACE_CLIENT_HOST
- REPLACE_CLIENT_IP

These values refer to the SSH client context evaluated
by sshd -T -C, not automatically to the server IP.

The template refuses to run until configured.

## 4. Installation on the target Linux server

First, create a VM snapshot or equivalent recovery point.

Copy the configured collector and sudoers example
to a temporary directory on the target server.

Validate the sudoers rule:

sudo visudo -cf ./secureops-scan.sudoers.example

Install the collector:

sudo install -o root -g root -m 0755 -T \
  ./secureops-ssh01-read \
  /usr/local/sbin/secureops-ssh01-read

Test the collector as administrator:

sudo /usr/local/sbin/secureops-ssh01-read

After confirming its output, install the sudoers rule:

sudo install -o root -g root -m 0440 -T \
  ./secureops-scan.sudoers.example \
  /etc/sudoers.d/secureops-scan

sudo visudo -c

Do not overwrite existing installation files without review.

## 5. Permission verification

Allowed command:

sudo -u secureops-scan sudo -n \
  /usr/local/sbin/secureops-ssh01-read

Expected: SSH-01 collection JSON.

Disallowed command:

sudo -u secureops-scan sudo -n /usr/bin/id

Expected: Permission denied or password required.

Additional arguments to the collector must also be denied.

## 6. Limitations

- Collector currently checks the global configuration and
  one configured root connection context.
- Full Match-rule coverage is not implemented.
- A vulnerable configuration does not automatically receive
  a numerical CVSS score.
- This collector does not modify SSH server settings.
- Different Linux distributions require validation before use.

## 7. Evidence and security

- Store scan evidence outside the source repository.
- Do not commit SSH private keys, passwords, or secrets.
- Verify SSH host keys before connecting.
- Review sudoers changes using visudo.
- Use the saved VM snapshot for recovery if necessary.
