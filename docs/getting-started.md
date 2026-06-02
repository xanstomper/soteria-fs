# Getting Started with Soteria

Welcome to Soteria — a modern encrypted security platform that protects your files with hardware-rooted encryption, intrusion detection, and recovery systems.

This guide walks you through installing Soteria, setting up protection, and understanding how it works.

---

## Installation

### Windows

1. Download the Soteria installer from the releases page.
2. Run `Soteria-Setup.msi`.
3. Follow the on-screen instructions.

### macOS

1. Download `Soteria.dmg` from the releases page.
2. Open the DMG and drag Soteria to Applications.
3. Open Soteria from Applications.

### Linux

```bash
# Debian/Ubuntu
sudo dpkg -i soteria_0.1.0_amd64.deb

# Fedora/RHEL
sudo rpm -i soteria-0.1.0.x86_64.rpm

# Or build from source
git clone https://github.com/example/soteria-fs.git
cd soteria-fs/rust-core
cargo build --release
sudo cp target/release/soteriad /usr/local/bin/
```

---

## First-Time Setup

When you open Soteria for the first time, the Setup Wizard guides you through:

### Step 1: System Check

Soteria scans your device for:
- **Hardware security (TPM)** — a chip on your motherboard that stores encryption keys
- **Boot integrity (Secure Boot)** — verifies your system starts safely
- **Storage** — finds the drive to protect
- **Recovery options** — checks for backup methods

Each check shows a green checkmark or an amber warning. Amber means the feature is optional but recommended.

### Step 2: Protection Mode

Choose how much protection you need:

| Mode | Best for | What you get |
|---|---|---|
| **Personal** | Most users | Full encryption, automatic key management, recovery key |
| **Professional** | Business data | Adds key rotation, audit logging, snapshot recovery |
| **Fortress** | High-risk users | Adds decoy protection, intrusion detection, aggressive rotation |

You can change this later in Settings.

### Step 3: Recovery Key

Your recovery key is the only way to access your files if you forget your password. Soteria asks you to save it in one or more ways:

- **USB Key** — save to a USB drive
- **Printed Sheet** — print a paper backup
- **Encrypted Backup File** — save an encrypted file to cloud storage

**Important:** Save at least two copies. Without your recovery key and password, your files cannot be recovered.

### Step 4: Protect

Soteria encrypts your files in the background. You can continue using your device while this happens.

---

## Using Soteria

### The Dashboard

The dashboard shows your protection status at a glance:

- **Protection Score** — a number from 0-100 showing overall security health
- **Encrypted Storage** — how much of your storage is protected
- **Recent Activity** — what Soteria has been doing in the background
- **Recovery Center** — the status of your recovery key backup

A green status means everything is working. Amber means something needs your attention. Red means action is required.

### Encrypting Files

Files are encrypted automatically when you save them to a protected area. You don't need to do anything manually.

To encrypt a specific file from the command line:

```bash
soteriad encrypt \
  --src /path/to/file.txt \
  --into /path/to/vault \
  --name myfile \
  --passphrase "your-passphrase"
```

### Decrypting Files

To decrypt a file:

```bash
soteriad decrypt \
  --from /path/to/vault \
  --name myfile \
  --passphrase "your-passphrase" \
  --output /path/to/recovered.txt
```

Or with a key file (from `share unlock`):

```bash
soteriad decrypt \
  --from /path/to/vault \
  --name myfile \
  --key-file /path/to/key.bin \
  --output /path/to/recovered.txt
```

### Sharing Files

Soteria uses post-quantum cryptography (ML-KEM-768 and ML-DSA-65) to share encrypted files securely.

**Step 1:** The recipient generates a keypair:
```bash
soteriad keygen --out /tmp/alice
```

**Step 2:** You add the recipient to your volume:
```bash
soteriad share add \
  --volume /path/to/vault/myfile.sot \
  --passphrase "your-passphrase" \
  --recipient-pk /tmp/alice.pk \
  --owner-sk /path/to/owner.dsa.sk
```

**Step 3:** The recipient unlocks the volume:
```bash
soteriad share unlock \
  --volume /path/to/vault/myfile.sot \
  --sk /tmp/alice.sk \
  --owner-pk /path/to/owner.dsa.pk \
  --out /tmp/alice.rootkey
```

**Step 4:** The recipient decrypts:
```bash
soteriad decrypt \
  --from /path/to/vault \
  --name myfile \
  --key-file /tmp/alice.rootkey \
  --output /tmp/recovered.txt
```

### Verifying Integrity

To check that your volumes haven't been tampered with:

```bash
soteriad verify --dir /path/to/vault
```

This checks the header integrity and lineage chain of every volume in the directory.

---

## Web Dashboard

Soteria includes a web dashboard for visual management.

### Starting the Dashboard

```bash
# Terminal 1: Start the API server
soteriad serve

# Terminal 2: Start the web UI
cd ui
bundle install
bundle exec ruby app.rb -p 4567
```

Open `http://localhost:4567` in your browser.

### Dashboard Pages

| Page | What it shows |
|---|---|
| **Dashboard** | Protection score, storage overview, recent activity, recovery status |
| **Protection** | Encrypted storage breakdown, security domains |
| **Threats** | Event stream, canary hits, decoy interactions, anomalies |
| **Keys** | Key lifecycle, rotation health, sharing management |
| **Recovery** | Recovery key status, verification, backup options |
| **Devices** | Connected devices and their trust status |
| **Audit Log** | BLAKE3-chained audit trail |
| **Settings** | Security mode, notifications, advanced mode |
| **Learning Center** | Explanations of security concepts |

---

## Command Reference

| Command | What it does |
|---|---|
| `soteriad encrypt` | Encrypt a file with a passphrase |
| `soteriad decrypt` | Decrypt with passphrase or key file |
| `soteriad list` | List volumes in a directory |
| `soteriad verify` | Verify volume integrity |
| `soteriad keygen` | Generate a keypair (ML-KEM-768 or ML-DSA-65) |
| `soteriad share add` | Add a recipient to a volume |
| `soteriad share remove` | Revoke a recipient |
| `soteriad share list` | List active and revoked recipients |
| `soteriad share unlock` | Recover the volume root key |
| `soteriad audit` | Inspect and verify the audit log |
| `soteriad serve` | Start the REST API for the web UI |

---

## Tips

- **Test your recovery key** every 30 days from the Recovery Center.
- **Keep at least two copies** of your recovery key in different locations.
- **Use Fortress mode** if you handle sensitive data or face elevated threats.
- **Check the event stream** periodically to see what Soteria is doing in the background.
- **Enable Secure Boot** in your firmware settings for maximum protection.
