import { PublicKey } from "@solana/web3.js";
import { getAttestationDecoder } from "sas-lib";

export interface VerificationPolicy {
  minLivenessBps: number;
  minGestureConfidenceBps?: number;
  minBodyPoseBps?: number;
  maxFatigueBucket: number;
  requiredGestureCode?: number;
  minHrvBucket?: number;
  requiredPatternCode?: number;
}

export interface BiometricAttestationPayload {
  subjectWallet: string;
  livenessBps: number;
  gestureConfidenceBps: number;
  bodyPoseBps?: number;
  hrvBucket: number;
  fatigueBucket: number;
  gestureCode: number;
  sessionHash: Uint8Array;
  verifiedAt: bigint;
  attestationKind: "single-action" | "session-pass";
  sessionExpiresAt: bigint;
  maxX402Calls: number;
  controllerWallet: string;
}

export interface SasBiometricAttestationData {
  subject_wallet: string;
  liveness_bps: number;
  gesture_confidence_bps?: number;
  body_pose_bps?: number;
  hrv_bucket: number;
  fatigue_bucket: number;
  gesture_code: number;
  session_hash: Uint8Array;
  verified_at: bigint | number;
  attestation_kind: number;
  session_expires_at: bigint | number;
  max_x402_calls: number;
  controller_wallet: string;
}

export interface SasAttestationRecord {
  nonce: string;
  credential: string;
  schema: string;
  data: Uint8Array;
  signer: string;
  expiry: bigint;
  tokenAccount: string;
}

export const defaultVerificationPolicy: VerificationPolicy = {
  minLivenessBps: 8_500,
  minGestureConfidenceBps: 8_000,
  minBodyPoseBps: 8_000,
  maxFatigueBucket: 3,
  minHrvBucket: 1,
  requiredPatternCode: 1,
  requiredGestureCode: 1,
};

const INNER_PAYLOAD_SIZE = 122;
const PUBKEY_BYTES = 32;
const U32_BYTES = 4;
const I64_BYTES = 8;

export function evaluateThresholds(
  payload: BiometricAttestationPayload,
  policy: VerificationPolicy = defaultVerificationPolicy,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];

  if (payload.livenessBps < policy.minLivenessBps) {
    reasons.push("liveness_below_threshold");
  }

  if (
    policy.minGestureConfidenceBps !== undefined &&
    payload.gestureConfidenceBps < policy.minGestureConfidenceBps
  ) {
    reasons.push("gesture_confidence_below_threshold");
  }

  if (policy.minBodyPoseBps !== undefined && (payload.bodyPoseBps ?? 0) < policy.minBodyPoseBps) {
    reasons.push("body_pose_below_threshold");
  }

  if (payload.fatigueBucket > policy.maxFatigueBucket) {
    reasons.push("fatigue_above_threshold");
  }

  if (policy.minHrvBucket !== undefined && payload.hrvBucket < policy.minHrvBucket) {
    reasons.push("hrv_below_threshold");
  }

  const requiredPatternCode = policy.requiredPatternCode ?? policy.requiredGestureCode;

  if (requiredPatternCode !== undefined && payload.gestureCode !== requiredPatternCode) {
    reasons.push("required_gesture_missing");
  }

  return {
    ok: reasons.length === 0,
    reasons,
  };
}

export function deserializeBiometricAttestationPayload(bytes: Uint8Array): BiometricAttestationPayload {
  if (bytes.length < INNER_PAYLOAD_SIZE) {
    throw new Error("Invalid biometric attestation payload length");
  }

  let offset = 0;
  const subjectWallet = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));
  offset += PUBKEY_BYTES;
  const livenessBps = readU16(bytes, offset);
  offset += 2;
  const gestureConfidenceBps = readU16(bytes, offset);
  offset += 2;
  const hrvBucket = bytes[offset++] ?? 0;
  const fatigueBucket = bytes[offset++] ?? 0;
  const gestureCode = bytes[offset++] ?? 0;
  const sessionHash = bytes.slice(offset, offset + 32);
  offset += 32;
  const verifiedAt = readI64(bytes, offset);
  offset += I64_BYTES;
  const attestationKind: BiometricAttestationPayload["attestationKind"] =
    bytes[offset++] === 1 ? "session-pass" : "single-action";
  const sessionExpiresAt = readI64(bytes, offset);
  offset += I64_BYTES;
  const maxX402Calls = readU16(bytes, offset);
  offset += 2;
  const controllerWallet = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));

  return {
    subjectWallet,
    livenessBps,
    gestureConfidenceBps,
    bodyPoseBps: gestureConfidenceBps,
    hrvBucket,
    fatigueBucket,
    gestureCode,
    sessionHash,
    verifiedAt,
    attestationKind,
    sessionExpiresAt,
    maxX402Calls,
    controllerWallet,
  };
}

export function deserializeSasAttestationRecord(bytes: Uint8Array): SasAttestationRecord {
  try {
    return deserializeMockSasAttestationRecord(bytes);
  } catch {
    const record = getAttestationDecoder().decode(bytes);
    return {
      nonce: record.nonce,
      credential: record.credential,
      schema: record.schema,
      data: Uint8Array.from(record.data),
      signer: record.signer,
      expiry: BigInt(record.expiry),
      tokenAccount: record.tokenAccount,
    };
  }
}

export function fromSasBiometricAttestationData(data: SasBiometricAttestationData): BiometricAttestationPayload {
  return {
    subjectWallet: data.subject_wallet,
    livenessBps: data.liveness_bps,
    gestureConfidenceBps: data.gesture_confidence_bps ?? data.body_pose_bps ?? 0,
    bodyPoseBps: data.body_pose_bps ?? data.gesture_confidence_bps ?? 0,
    hrvBucket: data.hrv_bucket,
    fatigueBucket: data.fatigue_bucket,
    gestureCode: data.gesture_code,
    sessionHash: Uint8Array.from(data.session_hash).slice(0, 32),
    verifiedAt: BigInt(data.verified_at),
    attestationKind: data.attestation_kind === 1 ? "session-pass" : "single-action",
    sessionExpiresAt: BigInt(data.session_expires_at),
    maxX402Calls: data.max_x402_calls,
    controllerWallet: data.controller_wallet,
  };
}

function deserializeMockSasAttestationRecord(bytes: Uint8Array): SasAttestationRecord {
  let offset = 0;
  const discriminator = bytes[offset++];

  if (discriminator !== 1) {
    throw new Error("Invalid mock SAS attestation discriminator");
  }

  const nonce = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));
  offset += PUBKEY_BYTES;
  const credential = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));
  offset += PUBKEY_BYTES;
  const schema = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));
  offset += PUBKEY_BYTES;
  const dataLength = readU32(bytes, offset);
  offset += U32_BYTES;
  const data = bytes.slice(offset, offset + dataLength);
  offset += dataLength;
  const signer = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));
  offset += PUBKEY_BYTES;
  const expiry = readI64(bytes, offset);
  offset += I64_BYTES;
  const tokenAccount = bytesToPublicKey(bytes.slice(offset, offset + PUBKEY_BYTES));

  return { nonce, credential, schema, data, signer, expiry, tokenAccount };
}

function bytesToPublicKey(value: Uint8Array): string {
  return new PublicKey(value).toBase58();
}

function readU16(buffer: Uint8Array, offset: number): number {
  return new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint16(offset, true);
}

function readU32(buffer: Uint8Array, offset: number): number {
  return new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(offset, true);
}

function readI64(buffer: Uint8Array, offset: number): bigint {
  return new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getBigInt64(offset, true);
}
