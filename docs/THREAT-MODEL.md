# SOTERIA-OMEGA Threat Model (Part 14)

## 1. Adversary classes

OMEGA assumes an adversary with one or more of the following
capabilities:

| Class | Capability                                                                  |
|-------|-----------------------------------------------------------------------------|
| A1    | Remote network attacker. Can probe, but cannot authenticate or break crypto.|
| A2    | Local network attacker. Can MITM the local network.                         |
| A3    | Authenticated local user. Can run arbitrary code as a non-privileged user.  |
| A4    | Local root. Can read all files, modify all processes, dump RAM.            |
| A5    | Coercer of one cleared operator. Can demand keys, with implicit violence.  |
| A6    | Coercer of two cleared operators simultaneously.                            |
| A7    | Physical access to a running machine (cold boot, DMA, firewire).            |
| A8    | Physical access to a powered-off machine (lost/stolen device).              |
| A9    | TEMPEST-grade EM capture within 1 metre.                                   |
| A10   | Long-term key recovery budget (harvest-now-decrypt-later, post-quantum).    |
| A11   | Supply-chain compromise of one hardware component.                          |

OMEGA is designed to be robust against A1-A5, A7, A8, A10, and A11
(software-fallback). A6 and A9 are out of scope.

## 2. Defended scenarios

| Scenario                                       | Class(es)   | OMEGA defence                                                                                  |
|------------------------------------------------|-------------|------------------------------------------------------------------------------------------------|
| Lost/stolen device                             | A8          | FDE (XTS-256), LUKS2 header, hidden volume                                                    |
| Compromised OS, attacker reads encrypted disk  | A4          | XTS-256 + master key in forked crypto process                                                  |
| Coercion of one operator                       | A5          | Two-person rule, witness sign, duress wipe                                                    |
| Cold-boot attack on running machine            | A7          | mlock + zeroize on drop (SecureBox) + forked crypto process                                   |
| Future quantum attacker with recorded traffic  | A10         | ML-KEM-768 hybrid (post-quantum KEM) for shared keys                                          |
| Operator in airplane, duress coercion          | A5, A7      | PanicButton (1 keystroke wipes RAM-resident keys in <100ms)                                    |
| RF emanation capture within 1 metre            | A9          | Software jamming + zone policy (HARDWARE EARD required for full defence)                      |
| Ransomware encrypts files in-place             | (insider)   | Entropy monitor + write-rate cap + extension blocklist + ancestry                             |
| Forged custody event in COMSEC ledger          | (insider)   | BLAKE3 chain + witness signature on every event                                               |
| Forged key release                             | A4          | Two-person rule requires BLAKE3-chained session + witness + classification binding            |
| Air-gapped network exfiltration                | A2, A3      | AirGapEnforcer blocks all non-loopback egress in `air-gap` mode                               |
| Tainted crypto library                         | A11         | FIPS POST + Software/Firmware Integrity Test (SFIT) at startup; refuse-to-start on failure     |
| Volume tampered with during transport          | (physical)  | Merkle proof + RS(255,223) error recovery (up to 16 byte erasures per stripe)                  |

## 3. Out-of-scope scenarios

| Scenario                                                | Reason                                                                                          |
|---------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| A6 (two operators colluding)                            | Insider-collusion; mitigations are organisational (dual-control assignment, polygraph, vetting)|
| A9 (TEMPEST RF emanation) without EARD hardware          | Pure software cannot mask RF; OMEGA logs `HardwareDependencyMissing` and refuses operation     |
| A11 (compromise of all hardware)                        | If every component is backdoored, no software can detect it                                     |
| Denial of service (volume destroyed)                    | OMEGA does not provide off-site backup; operator must plan separately                          |
| Side-channel on the *operator* (e.g., camera on keyboard) | Physical security is out of scope                                                              |
| Compromising TEMPEST emitter (if present)               | If the operator deploys a backdoored EARD, OMEGA is silent on that                             |
| Cold-boot with liquid nitrogen on DRAM                  | Defence in 100ms window is best-effort; operators should use DRAM scrambling (AMD SME/Intel TME) |

## 4. Per-part threat summary

### Part 1 — Classification & MLS

- **Defends**: insufficient-clearance read, downgrade write, cross-compartment leak.
- **Does not defend**: kernel-level bypass (the OS could still read
  classified memory if the user is running privileged).
- **Mitigation**: SELinux MLS / AppArmor / capability-sealed microkernel
  (out of scope; OMEGA is a crypto engine, not a kernel).

### Part 2 — Two-Person Rule

- **Defends**: coercion of one operator.
- **Does not defend**: coercion of two operators simultaneously,
  colluding operators, or social engineering of the witness.
- **Mitigation**: organisational dual-control assignment, polygraph,
  continuous evaluation (out of scope for the engine).

### Part 3 — TEMPEST

- **Defends**: software side channels (timing, cache, branch predictor).
- **Does not defend**: RF emanations, power analysis, acoustic emanations
  (without EARD hardware).
- **Mitigation**: shielded enclosure, filtered power, sound-dampened
  room, faraday cage (operator-provided).

### Part 4 — COMSEC Custody Chain

- **Defends**: forged custody events, unrecorded key destruction,
  unattended transitions.
- **Does not defend**: a compromised security officer who countersigns
  malicious events.
- **Mitigation**: separation of duties, multi-auditor witnesses.

### Part 5 — Emergency Zeroization

- **Defends**: coercion under time pressure (the operator can wipe in
  <100ms before revealing the key).
- **Does not defend**: an adversary who has already extracted the key
  from RAM before the operator can press the button; ColdWar is
  irreversible.
- **Mitigation**: physical security, randomised lockout so the
  adversary cannot predict the wipe window.

### Part 6 / 13 — Multi-Level Init Flow

- **Defends**: out-of-order or partial init (the engine refuses to
  open a volume whose init is incomplete).
- **Does not defend**: an operator who completes all 6 phases but
  with malicious intent (insider threat).
- **Mitigation**: cross-checks against the witness, the audit anchor,
  and the birth certificate.

### Part 7 — Operational Sovereignty

- **Defends**: network exfiltration, time-based replay attacks,
  metadata leakage.
- **Does not defend**: an operator who deliberately disarms the
  enforcer; an attacker with physical access to the network cable.
- **Mitigation**: physical security of the network.

### Part 9 — Forked Crypto Process

- **Defends**: control-plane compromise (attacker must also compromise
  the data plane to recover the live key).
- **Does not defend**: a kernel-level compromise of the data plane
  process.
- **Mitigation**: measured boot, TPM-sealed data plane, capability
  drop, seccomp-bpf filter (Linux).

### Part 10 — Merkle + Reed-Solomon

- **Defends**: random byte errors (Merkle), burst erasures up to 16
  bytes per 255-byte stripe (RS).
- **Does not defend**: large-scale corruption (the engine refuses
  the affected region).
- **Mitigation**: snapshot rollback via the existing `snapshot_engine`.

### Part 11 — Ransomware Defence

- **Defends**: in-place encryption attacks (entropy monitor), burst
  writes (rate cap), known ransomware extensions (blocklist), unknown-
  parent processes (ancestry walk on Linux).
- **Does not defend**: in-memory ransomware (writes via legitimate
  process), no extension change, low entropy over time.
- **Mitigation**: snapshot rollback, application allow-list (operator-
  configured).

### Part 12 — Hardware Root of Trust

- **Defends**: key extraction from disk (TPM seal), stolen operator
  credentials (FIDO2), replay attacks on hardware (PUF).
- **Does not defend**: a TPM silicon that is itself compromised.
- **Mitigation**: vendor diversity, supply-chain audits, attestation
  of TPM firmware (out of scope for the engine).

### Part 14 — Threat Model

- **Defends**: undocumented assumptions (this document is the
  authoritative answer to "what is the threat model?").
- **Does not defend**: a threat model that does not match reality
  (e.g., an operator who assumes RF emanation is safe when it isn't).

## 5. Trust boundaries

```
+-----------------+         +------------------+
|  Operator A     |         |  Operator B      |
|  (clearance: TS)|         |  (clearance: TS) |
+--------+--------+         +---------+--------+
         | shares                     | shares
         v                            v
+----------------------------------------+
|  soteriad (control plane)             |
|  - 6-phase init state machine          |
|  - TwoPersonRule session               |
|  - AirGapEnforcer                      |
|  - RansomwareDefense                   |
+--+----------------+----------------+
   | IPC            | IPC
   v                v
+--------+    +--------+
| TPM 2.0|    | FIDO2  |
+--------+    +--------+
```

Trust is *not* transitive. Each component assumes all the others
might be compromised; the only thing we trust is the operator's
hardware token and the operator's own intent.

## 6. Recovery scenarios

| Scenario                                     | Recovery procedure                                                        |
|----------------------------------------------|---------------------------------------------------------------------------|
| One operator loses credentials               | Re-enroll a new operator; revoke the lost one's shares via the COMSEC custody chain. |
| All Shamir shares lost                       | The volume is permanently lost. Operator must restore from off-site backup.|
| Audit log tampered                           | The BLAKE3 chain detects tampering; engine refuses to serve. Operator must restore from cold-storage audit log. |
| TPM reset                                    | Sealed blobs are no longer recoverable. Operator must re-run the 6-phase init. |
| FIPS POST fails                              | The engine refuses to start. Operator must reinstall the binary.          |
| ColdWar triggered by accident                | Re-initialize from Shamir shares; the COMSEC chain records the false alarm.|

## 7. Caveats

- The MVP is software-only. Hardware dependencies are logged but
  not enforced. Production deployment requires real TPM, FIDO2, and
  EARD.
- The `TpmManager` software fallback is *not* a security boundary.
  It exists so the engine can run in development environments
  without a TPM. A production operator must run on hardware with a
  real TPM 2.0 silicon and verify the engine's TPM seal/unseal
  against the real chip.
- The `Fido2Device` software fallback signs with a deterministic
  function of the host name. This is trivially replayable. A
  production operator must use real FIDO2 hardware and configure
  the engine to expect a CTAP2 attestation.

## 8. Cross-references

- IRONCLAD mechanism table: `soteria-core/src/omega/mod.rs::ironclad_table()`
- Architecture: `docs/SOTERIA-OMEGA-ARCHITECTURE.md`
- FDE base: `docs/FDE-ARCHITECTURE.md`
- FIPS: `docs/FIPS-SECURITY-POLICY.md`
- Audit log format: `rust-core/src/policy/audit_log.rs`
