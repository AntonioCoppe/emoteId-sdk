import { startTransition, useEffectEvent, useState } from "react";
import { deserializeAttestationData, getSchemaDecoder } from "sas-lib";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import {
  type SasBiometricAttestationData,
  type VerificationPolicy,
  defaultVerificationPolicy,
  deserializeBiometricAttestationPayload,
  deserializeSasAttestationRecord,
  evaluateThresholds,
  fromSasBiometricAttestationData,
} from "./schema.js";

export interface WalletMessageSigner {
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}

export interface VerifyAndAttestOptions {
  issuerBaseUrl: string;
  attestationKind?: "single-action" | "session-pass";
  sessionDurationSeconds?: number;
  maxX402Calls?: number;
  expirySeconds?: number;
  policy?: Partial<VerificationPolicy>;
  controllerWallet?: string;
  walletClient: WalletMessageSigner;
  fetchImpl?: typeof fetch;
  captureSummaryProvider?: (context: {
    sessionId: string;
    providerSessionId: string;
  }) => Promise<{
    durationSeconds: number;
    framesProcessed: number;
    liveness?: number;
    bodyPose?: number;
    patternConfidence?: number;
    hrv?: number;
    fatigue?: number;
    bpm?: number;
    patternCode?: number;
    gestureCode?: number;
  } | undefined>;
}

export interface VerifyAndAttestResult {
  attestationPda: string;
  txSignature: string;
  payload: unknown;
  reasons: string[];
}

export interface VerificationRpc {
  getAccountInfo?(attestationPda: string): Promise<{ data: Uint8Array | Buffer | string } | null>;
  getAttestation?(attestationPda: string): Promise<{ accountData: Uint8Array } | null>;
}

export async function verifyAndAttest(
  wallet: string,
  options: VerifyAndAttestOptions,
): Promise<VerifyAndAttestResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const startResponse = await fetchImpl(`${options.issuerBaseUrl}/api/v1/verification-sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      wallet,
      attestationKind: options.attestationKind ?? "single-action",
      sessionDurationSeconds: options.sessionDurationSeconds,
      maxX402Calls: options.maxX402Calls,
      expirySeconds: options.expirySeconds,
      policy: options.policy,
      controllerWallet: options.controllerWallet,
    }),
  });

  if (!startResponse.ok) {
    throw new Error(`Failed to start verification session: ${startResponse.status}`);
  }

  const started = (await startResponse.json()) as {
    sessionId: string;
    challengeBase64: string;
    providerSessionId?: string;
  };
  const challenge = Uint8Array.from(Buffer.from(started.challengeBase64, "base64"));
  const signature = await options.walletClient.signMessage(challenge);
  const captureSummary = await options.captureSummaryProvider?.({
    sessionId: started.sessionId,
    providerSessionId: started.providerSessionId ?? "",
  });
  const completeResponse = await fetchImpl(
    `${options.issuerBaseUrl}/api/v1/verification-sessions/${started.sessionId}/complete`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet,
        signatureBase64: Buffer.from(signature).toString("base64"),
        captureSummary,
      }),
    },
  );

  if (!completeResponse.ok) {
    throw new Error(`Failed to complete verification session: ${completeResponse.status}`);
  }

  const completed = (await completeResponse.json()) as {
    approved: boolean;
    reasons: string[];
    attestation?: { attestationPda: string; txSignature: string };
    payload?: unknown;
  };

  if (!completed.approved || !completed.attestation) {
    throw new Error(`Verification rejected: ${completed.reasons.join(", ")}`);
  }

  return {
    attestationPda: completed.attestation.attestationPda,
    txSignature: completed.attestation.txSignature,
    payload: completed.payload,
    reasons: completed.reasons,
  };
}

export async function verifyAttestation(
  rpc: VerificationRpc,
  input: {
    attestationPda: string;
    wallet: string;
    policy?: Partial<VerificationPolicy>;
  },
): Promise<{ valid: boolean; reasons: string[]; payload?: ReturnType<typeof deserializeBiometricAttestationPayload> }> {
  const accountData = await getRawAccountData(rpc, input.attestationPda);

  if (!accountData) {
    return {
      valid: false,
      reasons: ["attestation_not_found"],
    };
  }

  const record = deserializeSasAttestationRecord(accountData);
  const payload = await decodePayload(rpc, record.schema, record.data);
  const reasons: string[] = [];

  if (payload.subjectWallet !== input.wallet) {
    reasons.push("wallet_mismatch");
  }

  if (record.expiry < BigInt(Math.floor(Date.now() / 1000))) {
    reasons.push("attestation_expired");
  }

  const thresholdCheck = evaluateThresholds(payload, {
    ...defaultVerificationPolicy,
    ...input.policy,
  });
  reasons.push(...thresholdCheck.reasons);

  return {
    valid: reasons.length === 0,
    reasons,
    payload,
  };
}

async function decodePayload(rpc: VerificationRpc, schemaPda: string, payloadBytes: Uint8Array) {
  try {
    const schemaAccountData = await getRawAccountData(rpc, schemaPda);

    if (schemaAccountData) {
      const schema = getSchemaDecoder().decode(schemaAccountData);
      const decoded = deserializeAttestationData(schema, payloadBytes) as SasBiometricAttestationData;
      return fromSasBiometricAttestationData(decoded);
    }
  } catch {
    return deserializeBiometricAttestationPayload(payloadBytes);
  }

  return deserializeBiometricAttestationPayload(payloadBytes);
}

async function getRawAccountData(rpc: VerificationRpc, address: string): Promise<Uint8Array | null> {
  if (rpc.getAccountInfo) {
    const account = await rpc.getAccountInfo(address);
    return typeof account?.data === "string"
      ? Uint8Array.from(Buffer.from(account.data, "base64"))
      : account?.data
        ? Uint8Array.from(account.data)
        : null;
  }

  if (rpc.getAttestation) {
    const account = await rpc.getAttestation(address);
    return account?.accountData ?? null;
  }

  return null;
}

export function createDemoWalletClient(seed?: Uint8Array): { wallet: string; client: WalletMessageSigner; keypair: Keypair } {
  const keypair = Keypair.fromSeed(resolveDemoSeed(seed));

  return {
    wallet: keypair.publicKey.toBase58(),
    keypair,
    client: {
      async signMessage(message: Uint8Array) {
        return nacl.sign.detached(message, keypair.secretKey);
      },
    },
  };
}

function resolveDemoSeed(seed?: Uint8Array): Uint8Array {
  if (seed && seed.length >= 32) {
    return seed.slice(0, 32);
  }

  const output = new Uint8Array(32);

  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(output);
    return output;
  }

  output.set(nacl.randomBytes(32));
  return output;
}

export function useEmoteID(options: Omit<VerifyAndAttestOptions, "walletClient"> & { walletClient: WalletMessageSigner | null }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verifyEvent = useEffectEvent(async (wallet: string) => {
    if (!options.walletClient) {
      throw new Error("A wallet client is required to sign the verification challenge");
    }

    return verifyAndAttest(wallet, {
      ...options,
      walletClient: options.walletClient,
    });
  });

  async function verify(wallet: string) {
    startTransition(() => {
      setLoading(true);
      setError(null);
    });

    try {
      const result = await verifyEvent(wallet);
      startTransition(() => {
        setLoading(false);
      });
      return result;
    } catch (caughtError) {
      startTransition(() => {
        setLoading(false);
        setError(caughtError instanceof Error ? caughtError.message : "Verification failed");
      });
      throw caughtError;
    }
  }

  return { verify, loading, error };
}
