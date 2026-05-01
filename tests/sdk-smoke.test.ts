import { describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import {
  createDemoWalletClient,
  verifyAndAttest,
  verifyAndIssueTrustCredential,
  verifyTrustCredentialStatus,
} from "../src/index";

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
});
