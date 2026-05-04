import { afterEach, describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import {
  completeTrustSession,
  createDemoWalletClient,
  decodeLivenessResultToken,
  getPasskeyAssertion,
  revokeTrustCredential,
  verifyAndAttest,
  verifyAndIssueTrustCredential,
  verifyTrustCredentialStatus,
} from "../src/index";
import {
  defaultVerificationPolicy,
  evaluateThresholds,
  fromSasBiometricAttestationData,
} from "../src/schema";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("@emoteai/sas-biometric", () => {
  it("creates a demo wallet client that signs messages", async () => {
    const { wallet, client } = createDemoWalletClient(new Uint8Array(32).fill(7));
    const message = new TextEncoder().encode("emoteid");
    const signature = await client.signMessage(message);

    expect(wallet).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
    expect(signature).toHaveLength(nacl.sign.signatureLength);
  });

  it("completes a mocked verification flow", async () => {
    const { wallet, client } = createDemoWalletClient(new Uint8Array(32).fill(9));
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          sessionId: "session-123",
          challengeBase64: Buffer.from("challenge").toString("base64"),
          providerSessionId: "provider-session-123",
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          approved: true,
          reasons: [],
          attestation: {
            attestationPda: "11111111111111111111111111111111",
            txSignature: "22222222222222222222222222222222",
          },
          payload: { attestationKind: "session-pass" },
        }),
      );

    const result = await verifyAndAttest(wallet, {
      issuerBaseUrl: "https://example.test",
      attestationKind: "session-pass",
      walletClient: client,
      fetchImpl: fetchMock,
      captureSummaryProvider: async () => ({
        durationSeconds: 12,
        framesProcessed: 240,
        liveness: 0.95,
      }),
    });

    expect(result.attestationPda).toBe("11111111111111111111111111111111");
    expect(result.txSignature).toBe("22222222222222222222222222222222");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("completes a mocked v2 trust credential flow", async () => {
    const { wallet, client } = createDemoWalletClient(new Uint8Array(32).fill(11));
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          trustSessionId: "trust-session-123",
          subjectHash: "sha256:subject",
          walletChallengeBase64: Buffer.from("trust challenge").toString("base64"),
          passkeyOptions: {
            challenge: "passkey-challenge",
            rpId: "example.test",
            userVerification: "preferred",
            timeoutMs: 60_000,
          },
          emoteChallenge: {
            provider: "emote-api",
            challengeId: "challenge-123",
            challengeHash: "sha256:challenge",
            expiresAt: Date.now() + 60_000,
            steps: [{ id: "gesture-1", kind: "gesture", category: "Open_Palm", prompt: "Hold open palm" }],
          },
          expiresAt: Date.now() + 60_000,
          policy: { id: "default-bank-mvp" },
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          approved: true,
          reasons: [],
          assuranceLevel: "EID-3",
          trustScoreBps: 9300,
          riskScoreBps: 700,
          credentials: [
            {
              type: "w3c-vc",
              credentialId: "w3c-vc_123",
              revocationId: "rev_123",
              credential: {
                type: ["VerifiableCredential", "EmoteIDTrustCredential"],
              },
              proof: "signed.vc.proof",
            },
          ],
        }),
      );

    const result = await verifyAndIssueTrustCredential({
      issuerBaseUrl: "https://example.test",
      subject: { type: "wallet", wallet },
      requestedOutputs: ["w3c-vc"],
      walletClient: client,
      fetchImpl: fetchMock,
      livenessResultProvider: async ({ started }) => `signed-token-for-${started.trustSessionId}`,
      passkeyAssertionProvider: async (options) => ({
        credentialId: "passkey-test",
        challenge: options!.challenge,
        signatureBase64: "passkey-signature",
        clientDataJSON: Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: options!.challenge })).toString(
          "base64url",
        ),
        authenticatorData: Buffer.from("authenticator-data").toString("base64url"),
      }),
    });

    expect(result.approved).toBe(true);
    expect(result.credentials[0]?.type).toBe("w3c-vc");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.test/api/v2/trust-sessions/trust-session-123/complete",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("checks v2 credential status", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      Response.json({
        credentialId: "cred-123",
        status: "active",
      }),
    );

    await expect(
      verifyTrustCredentialStatus({
        issuerBaseUrl: "https://example.test",
        credentialId: "cred-123",
        fetchImpl: fetchMock,
      }),
    ).resolves.toEqual({
      credentialId: "cred-123",
      status: "active",
    });
  });

  it("preserves legacy body-pose thresholds separately from gesture confidence", () => {
    const payload = {
      subjectWallet: "11111111111111111111111111111111",
      livenessBps: 9_500,
      gestureConfidenceBps: 9_000,
      bodyPoseBps: 1_000,
      hrvBucket: 3,
      fatigueBucket: 1,
      gestureCode: 1,
      sessionHash: new Uint8Array(32),
      verifiedAt: 1n,
      attestationKind: "session-pass" as const,
      sessionExpiresAt: 2n,
      maxX402Calls: 1_000,
      controllerWallet: "11111111111111111111111111111111",
    };

    expect(
      evaluateThresholds(payload, {
        ...defaultVerificationPolicy,
        minGestureConfidenceBps: 8_000,
        minBodyPoseBps: 8_000,
      }),
    ).toMatchObject({
      ok: false,
      reasons: expect.arrayContaining(["body_pose_below_threshold"]),
    });
    expect(
      fromSasBiometricAttestationData({
        subject_wallet: payload.subjectWallet,
        liveness_bps: payload.livenessBps,
        gesture_confidence_bps: payload.gestureConfidenceBps,
        body_pose_bps: payload.bodyPoseBps,
        hrv_bucket: payload.hrvBucket,
        fatigue_bucket: payload.fatigueBucket,
        gesture_code: payload.gestureCode,
        session_hash: payload.sessionHash,
        verified_at: payload.verifiedAt,
        attestation_kind: 1,
        session_expires_at: payload.sessionExpiresAt,
        max_x402_calls: payload.maxX402Calls,
        controller_wallet: payload.controllerWallet,
      }).bodyPoseBps,
    ).toBe(1_000);
  });

  it("signs the plain wallet challenge when base64 challenge compatibility field is absent", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      Response.json({
        approved: true,
        reasons: [],
        assuranceLevel: "EID-3",
        trustScoreBps: 9_300,
        riskScoreBps: 700,
        credentials: [],
      }),
    );
    const signedMessages: string[] = [];

    await completeTrustSession(
      {
        trustSessionId: "trust-session-plain",
        subjectHash: "sha256:subject",
        walletChallenge: "plain trust challenge",
        emoteChallenge: {
          provider: "emote-api",
          challengeId: "challenge-123",
          challengeHash: "sha256:challenge",
          expiresAt: Date.now() + 60_000,
          steps: [],
        },
        expiresAt: Date.now() + 60_000,
        policy: {},
      },
      {
        issuerBaseUrl: "https://example.test",
        wallet: "11111111111111111111111111111111",
        walletClient: {
          async signMessage(message) {
            signedMessages.push(new TextDecoder().decode(message));
            return message;
          },
        },
        livenessResultToken: "token",
        fetchImpl: fetchMock,
      },
    );

    const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const body = JSON.parse(String(request.body)) as { walletSignatureBase64?: string };
    expect(signedMessages).toEqual(["plain trust challenge"]);
    expect(Buffer.from(body.walletSignatureBase64 ?? "", "base64").toString("utf8")).toBe("plain trust challenge");
  });

  it("returns serialized WebAuthn assertion fields from the browser passkey helper", async () => {
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({
        type: "webauthn.get",
        challenge: "challenge",
        origin: "https://example.test",
      }),
    );
    const authenticatorData = new Uint8Array([1, 2, 3, 4]);
    const signature = new Uint8Array([5, 6, 7, 8]);
    const get = vi.fn().mockResolvedValue({
      id: "credential-id",
      response: {
        signature: signature.buffer,
        clientDataJSON: clientDataJSON.buffer,
        authenticatorData: authenticatorData.buffer,
      },
    });
    vi.stubGlobal("navigator", { credentials: { get } });
    vi.stubGlobal("Buffer", undefined);

    await expect(
      getPasskeyAssertion({
        challenge: "Y2hhbGxlbmdl",
        rpId: "example.test",
        userVerification: "preferred",
        timeoutMs: 60_000,
      }),
    ).resolves.toMatchObject({
      credentialId: "credential-id",
      signatureBase64: "BQYHCA==",
      clientDataJSON: btoa(String.fromCharCode(...clientDataJSON)),
      authenticatorData: "AQIDBA==",
    });
    expect(get).toHaveBeenCalledWith({
      publicKey: expect.objectContaining({
        rpId: "example.test",
        userVerification: "preferred",
        timeout: 60_000,
      }),
    });
  });

  it("decodes deployed Emote liveness result token claims", () => {
    const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "emote-liveness-prod" })).toString(
      "base64url",
    );
    const payload = Buffer.from(
      JSON.stringify({
        iss: "https://api.emote.ai",
        aud: "emoteid",
        sessionId: "trust-session-123",
        challengeHash: "sha256:challenge",
        status: "passed",
        scores: {
          overall: 94,
          gesture: 91,
          expression: 87,
          blinkHold: 100,
          dotTracking: 89,
        },
        spoofRiskScore: 0.06,
      }),
    ).toString("base64url");

    expect(decodeLivenessResultToken(`${header}.${payload}.signature`)).toMatchObject({
      header: { kid: "emote-liveness-prod" },
      claims: {
        iss: "https://api.emote.ai",
        aud: "emoteid",
        sessionId: "trust-session-123",
        status: "passed",
      },
    });
  });

  it("sends admin authorization when revoking a trust credential", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      Response.json({
        credentialId: "cred-123",
        status: "revoked",
        reason: "customer_request",
      }),
    );

    await expect(
      revokeTrustCredential({
        issuerBaseUrl: "https://example.test",
        credentialId: "cred-123",
        actor: "admin:test",
        reason: "customer_request",
        adminToken: "admin-secret",
        fetchImpl: fetchMock,
      }),
    ).resolves.toMatchObject({
      credentialId: "cred-123",
      status: "revoked",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://example.test/api/v2/credentials/cred-123/revoke",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ authorization: "Bearer admin-secret" }),
      }),
    );
  });
});
