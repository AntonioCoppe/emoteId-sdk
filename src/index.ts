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

export type CredentialOutputType = "sas" | "w3c-vc" | "sd-jwt" | "signed-json";

export type AssuranceLevel = "EID-0" | "EID-1" | "EID-2" | "EID-3" | "EID-4" | "EID-5";

export interface TrustSubject {
  type: "wallet" | "institution-account" | "hybrid";
  tenantId?: string;
  wallet?: string;
  institutionAccountId?: string;
}

export interface PasskeyRequestOptions {
  challenge: string;
  rpId: string;
  userVerification: "preferred" | "required";
  timeoutMs: number;
}

export interface PasskeyAssertion {
  credentialId: string;
  challenge: string;
  signatureBase64: string;
  clientDataJSON?: string;
  authenticatorData?: string;
}

export interface EmoteChallengeStep {
  id: string;
  kind: "gesture" | "expression" | "blink-hold" | "dot-tracking";
  category: string;
  prompt: string;
  holdMs?: number;
  targets?: ReadonlyArray<{ x: number; y: number; radius: number }>;
  timeLimitMs?: number;
}

export interface EmoteChallengeBootstrap {
  provider: "emote-api";
  challengeId: string;
  challengeHash: string;
  expiresAt: number;
  steps: readonly EmoteChallengeStep[];
}

export interface StartTrustSessionResponse {
  trustSessionId: string;
  subjectHash: string;
  walletChallengeBase64?: string;
  walletChallenge?: string;
  passkeyOptions?: PasskeyRequestOptions;
  emoteChallenge: EmoteChallengeBootstrap;
  expiresAt: number;
  policy: unknown;
}

export interface IssuedTrustCredential {
  type: CredentialOutputType;
  credentialId: string;
  revocationId: string;
  credential: unknown;
  proof?: string;
}

export interface CompleteTrustSessionResponse {
  approved: boolean;
  reasons: string[];
  assuranceLevel: AssuranceLevel;
  trustScoreBps: number;
  riskScoreBps: number;
  credentials: readonly IssuedTrustCredential[];
  evidence?: unknown;
}

export interface CredentialStatusResponse {
  credentialId: string;
  status: "active" | "expired" | "suspended" | "revoked";
  reason?: string;
  revokedAt?: number;
  expiresAt?: number;
}

export interface ClientCaptureSummary {
  durationSeconds: number;
  framesProcessed: number;
  liveness?: number;
  gestureConfidence?: number;
  challengeConfidence?: number;
  bodyPose?: number;
  patternConfidence?: number;
  hrv?: number;
  fatigue?: number;
  bpm?: number;
  gestureCode?: number;
  challengeCode?: number;
  patternCode?: number;
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
  }) => Promise<ClientCaptureSummary | undefined>;
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

export interface VerifyAndIssueTrustCredentialOptions {
  issuerBaseUrl: string;
  subject: TrustSubject;
  requestedOutputs?: readonly CredentialOutputType[];
  policy?: Record<string, unknown>;
  actionContext?: Record<string, unknown>;
  walletClient?: WalletMessageSigner;
  fetchImpl?: typeof fetch;
  livenessResultProvider: (context: {
    started: StartTrustSessionResponse;
  }) => Promise<string>;
  passkeyAssertionProvider?: (options: PasskeyRequestOptions | undefined) => Promise<PasskeyAssertion | undefined>;
}

export async function startTrustSession(
  options: Pick<
    VerifyAndIssueTrustCredentialOptions,
    "issuerBaseUrl" | "subject" | "requestedOutputs" | "policy" | "actionContext" | "fetchImpl"
  >,
): Promise<StartTrustSessionResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(`${trimBaseUrl(options.issuerBaseUrl)}/api/v2/trust-sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      subject: options.subject,
      requestedOutputs: options.requestedOutputs,
      policy: options.policy,
      actionContext: options.actionContext,
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to start trust session: ${response.status}`);
  }

  return (await response.json()) as StartTrustSessionResponse;
}

export async function completeTrustSession(
  started: StartTrustSessionResponse,
  options: {
    issuerBaseUrl: string;
    wallet?: string;
    walletClient?: WalletMessageSigner;
    passkeyAssertion?: PasskeyAssertion;
    livenessResultToken: string;
    requestedOutputs?: readonly CredentialOutputType[];
    fetchImpl?: typeof fetch;
  },
): Promise<CompleteTrustSessionResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const walletSignatureBase64 =
    started.walletChallengeBase64 && options.walletClient
      ? Buffer.from(
          await options.walletClient.signMessage(Uint8Array.from(Buffer.from(started.walletChallengeBase64, "base64"))),
        ).toString("base64")
      : undefined;
  const response = await fetchImpl(
    `${trimBaseUrl(options.issuerBaseUrl)}/api/v2/trust-sessions/${started.trustSessionId}/complete`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet: options.wallet,
        walletSignatureBase64,
        passkeyAssertion: options.passkeyAssertion,
        livenessResultToken: options.livenessResultToken,
        requestedOutputs: options.requestedOutputs,
      }),
    },
  );

  if (!response.ok) {
    throw new Error(`Failed to complete trust session: ${response.status}`);
  }

  return (await response.json()) as CompleteTrustSessionResponse;
}

export async function verifyAndIssueTrustCredential(
  options: VerifyAndIssueTrustCredentialOptions,
): Promise<CompleteTrustSessionResponse> {
  const started = await startTrustSession(options);
  const livenessResultToken = await options.livenessResultProvider({ started });
  const passkeyAssertion = await options.passkeyAssertionProvider?.(started.passkeyOptions);
  const completed = await completeTrustSession(started, {
    issuerBaseUrl: options.issuerBaseUrl,
    wallet: options.subject.wallet,
    walletClient: options.walletClient,
    passkeyAssertion,
    livenessResultToken,
    requestedOutputs: options.requestedOutputs,
    fetchImpl: options.fetchImpl,
  });

  if (!completed.approved) {
    throw new Error(`Trust verification rejected: ${completed.reasons.join(", ")}`);
  }

  return completed;
}

export async function verifyTrustCredentialStatus(options: {
  issuerBaseUrl: string;
  credentialId: string;
  fetchImpl?: typeof fetch;
}): Promise<CredentialStatusResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(
    `${trimBaseUrl(options.issuerBaseUrl)}/api/v2/credentials/${options.credentialId}/status`,
  );

  if (!response.ok) {
    throw new Error(`Failed to verify trust credential status: ${response.status}`);
  }

  return (await response.json()) as CredentialStatusResponse;
}

export async function revokeTrustCredential(options: {
  issuerBaseUrl: string;
  credentialId: string;
  actor: string;
  reason: string;
  fetchImpl?: typeof fetch;
}): Promise<CredentialStatusResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(
    `${trimBaseUrl(options.issuerBaseUrl)}/api/v2/credentials/${options.credentialId}/revoke`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actor: options.actor,
        reason: options.reason,
      }),
    },
  );

  if (!response.ok) {
    throw new Error(`Failed to revoke trust credential: ${response.status}`);
  }

  return (await response.json()) as CredentialStatusResponse;
}

export async function getPasskeyAssertion(options: PasskeyRequestOptions): Promise<PasskeyAssertion> {
  if (typeof navigator === "undefined" || !navigator.credentials?.get) {
    throw new Error("WebAuthn is not available in this environment");
  }

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: base64UrlToArrayBuffer(options.challenge),
      rpId: options.rpId,
      userVerification: options.userVerification,
      timeout: options.timeoutMs,
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error("Passkey assertion was cancelled");
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    credentialId: credential.id,
    challenge: options.challenge,
    signatureBase64: arrayBufferToBase64(response.signature),
    clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
    authenticatorData: arrayBufferToBase64(response.authenticatorData),
  };
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
        captureSummary: captureSummary ? normalizeCaptureSummary(captureSummary) : undefined,
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

export function normalizeCaptureSummary(summary: ClientCaptureSummary): ClientCaptureSummary {
  const gestureConfidence =
    summary.gestureConfidence ?? summary.challengeConfidence ?? summary.patternConfidence ?? summary.bodyPose;
  const gestureCode = summary.gestureCode ?? summary.challengeCode ?? summary.patternCode;

  return {
    ...summary,
    gestureConfidence,
    gestureCode,
    bodyPose: summary.bodyPose ?? gestureConfidence,
    patternConfidence: summary.patternConfidence ?? gestureConfidence,
    patternCode: summary.patternCode ?? gestureCode,
  };
}

export function decodeSignedCredential(token: string): { header: unknown; payload: unknown; signature: string } {
  const parts = token.split(".");

  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new Error("Invalid signed credential token");
  }

  return {
    header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as unknown,
    payload: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as unknown,
    signature: parts[2],
  };
}

function trimBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  const output = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(output).set(bytes);
  return output;
}

function arrayBufferToBase64(value: ArrayBuffer): string {
  return Buffer.from(value).toString("base64");
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
