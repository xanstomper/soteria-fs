import { invoke } from "@tauri-apps/api/core";

// ── Types ──────────────────────────────────────────────────────────

export interface ProtectionStatus {
  score: number;
  status: string;
  message: string;
  boot_chain: string;
  tpm: string;
  keys: string;
  recovery: string;
}

export interface StorageOverview {
  total_bytes: number;
  encrypted_bytes: number;
  domain_count: number;
  file_count: number;
}

export interface KeyInfo {
  name: string;
  key_type: string;
  status: string;
  rotation_due: string;
}

export interface KeyLifecycle {
  rotation_health: string;
  next_rotation: string;
  total_keys: number;
  keys: KeyInfo[];
}

export interface EncryptRequest {
  src: string;
  into: string;
  name: string;
  passphrase: string;
}

export interface EncryptResult {
  ok: boolean;
  path: string;
  algorithm: string;
  plaintext_size: number;
  block_count: number;
}

export interface DecryptRequest {
  from: string;
  name: string;
  passphrase: string;
  output: string;
}

export interface DecryptResult {
  ok: boolean;
  output: string;
  recovered_size: number;
}

export interface KeygenRequest {
  scheme: string;
  out: string;
}

export interface KeygenResult {
  ok: boolean;
  public_key: string;
  secret_key: string;
  scheme: string;
}

export interface TpmStatus {
  available: boolean;
  provider: string;
}

export interface RecoveryStatus {
  verified: boolean;
  last_tested: string;
  backup_count: number;
}

export interface EventInfo {
  id: number;
  timestamp: number;
  category: string;
  severity: string;
  source: string;
  message: string;
}

// ── Commands ────────────────────────────────────────────────────────

export async function getProtectionStatus(): Promise<ProtectionStatus> {
  return invoke("get_protection_status");
}

export async function getStorageOverview(): Promise<StorageOverview> {
  return invoke("get_storage_overview");
}

export async function getKeyLifecycle(): Promise<KeyLifecycle> {
  return invoke("get_key_lifecycle");
}

export async function encryptFile(req: EncryptRequest): Promise<EncryptResult> {
  return invoke("encrypt_file", { req });
}

export async function decryptFile(req: DecryptRequest): Promise<DecryptResult> {
  return invoke("decrypt_file", { req });
}

export async function generateKeypair(
  req: KeygenRequest
): Promise<KeygenResult> {
  return invoke("generate_keypair", { req });
}

export async function getTpmStatus(): Promise<TpmStatus> {
  return invoke("get_tpm_status");
}

export async function getRecoveryStatus(): Promise<RecoveryStatus> {
  return invoke("get_recovery_status");
}

export async function getEvents(): Promise<EventInfo[]> {
  return invoke("get_events");
}
