# Frequently Asked Questions

## General

### What is Soteria?

Soteria is an encrypted security platform that protects your files with hardware-rooted encryption, intrusion detection, and recovery systems. It combines proven cryptographic primitives into a hardened system architecture.

### How is Soteria different from VeraCrypt?

| | VeraCrypt | Soteria |
|---|---|---|
| Encryption model | Single volume, all-or-nothing | Multi-domain, per-block encryption |
| Key management | Static keys, manual rotation | Automatic rotation, hardware-bound |
| Threat detection | None | Canary system, anomaly detection, decoy filesystem |
| Recovery | Poorly explained, hidden | Front-and-center, guided, verifiable |
| Usability | Technical dialogs, outdated UI | Modern dashboard, progressive disclosure |

### Is Soteria's encryption stronger than VeraCrypt's?

No. Both use vetted AEAD primitives (AES-256-GCM, XChaCha20-Poly1305). Soteria is better because of its **architecture** — per-block key isolation, capability-scoped access, anomaly detection, and blast radius containment — not because it uses stronger algorithms.

### What does "Aegis" mean?

Aegis is the internal encryption and protection engine that powers Soteria. In Greek mythology, the Aegis is the shield of Zeus and Athena. Soteria is the goddess of safety and deliverance. Together: Soteria delivers you to safety; Aegis is the shield that protects you on the way.

---

## Security

### What encryption does Soteria use?

- **Data encryption:** XChaCha20-Poly1305 (default) or AES-256-GCM
- **Key derivation:** Argon2id (passphrase → root key), HKDF-SHA256 (per-block keys)
- **Hashing:** BLAKE3 (integrity, lineage, audit chain)
- **Post-quantum sharing:** ML-KEM-768 (key wrapping), ML-DSA-65 (envelope signatures)

### What is the TPM?

The TPM (Trusted Platform Module) is a small security chip on your motherboard. It stores part of your encryption key in hardware, so even if someone removes your hard drive, they can't decrypt it without the original device.

### What are canaries?

Canaries are invisible "tripwires" placed in your protected storage. If an unauthorized program touches one, Soteria detects it and can automatically restrict access.

### What is the honey filesystem?

The honey filesystem creates fake files that look real. If an attacker accesses them, Soteria knows they're snooping. It's like leaving a fake wallet on your desk.

### What is key rotation?

Periodically, Soteria changes your encryption keys — like changing the locks on your house. This limits the window of exposure if a key were ever compromised.

### Can Soteria be brute-forced?

Soteria uses Argon2id with OWASP 2024 minimum parameters (19 MiB memory, 2 iterations). This makes offline brute-force attacks computationally expensive. However, a weak passphrase can still be guessed — use a strong, unique passphrase.

---

## Recovery

### What if I forget my password?

Use your recovery key. It was generated during setup and saved to your chosen backup method (USB, printed sheet, or encrypted file).

### What if I lose my recovery key AND forget my password?

Your files cannot be recovered. This is by design — it means no one else can recover them either. This is why we recommend saving at least two copies of your recovery key.

### How do I test my recovery key?

Open the Recovery Center in the dashboard and click "Verify Recovery Key." This confirms your backup works without unlocking your device.

### How often should I test my recovery key?

Every 30 days. Soteria will remind you if you haven't tested recently.

---

## Troubleshooting

### Soteria says "daemon is not running"

The web dashboard needs the Soteria API server to be running:

```bash
soteriad serve
```

Then start the web UI:

```bash
cd ui
bundle exec ruby app.rb -p 4567
```

### I get "passphrase does not unlock this volume"

The passphrase you entered doesn't match the one used to encrypt the volume. Double-check your passphrase. If you've forgotten it, use your recovery key.

### I get "fingerprint mismatch" when unlocking a share

The share file doesn't match the volume's root key. This can happen if:
- You're using a share file from a different volume
- The volume's root key has been rotated since the share was created
- The share file has been tampered with

### I get "no envelope matches this secret key"

The secret key you're using doesn't match any active recipient in the share file. Check that:
- You're using the correct `.sk` file
- Your access hasn't been revoked by the volume owner

### I get "envelope signature failed verification"

The ML-DSA-65 signature on the envelope doesn't match. This means:
- The envelope was tampered with, OR
- You're using the wrong owner public key

Verify you have the correct owner's `.dsa.pk` file.

### The dashboard shows "Attention Needed"

Click the amber status indicator to see what needs your attention. Common causes:
- Key rotation is overdue
- Recovery key hasn't been tested recently
- A new device was connected

### How do I change my security mode?

Go to Settings → Security Mode and select a different mode. Changes take effect immediately.

### How do I add a new protected folder?

Go to Protection → Create Domain. Enter a name and path for the new domain.

### How do I revoke a recipient's access?

```bash
soteriad share remove \
  --volume /path/to/volume.sot \
  --passphrase "your-passphrase" \
  --recipient-pk /path/to/recipient.pk \
  --reason "reason for revocation"
```

The recipient's envelope is preserved in the history but is no longer active.
