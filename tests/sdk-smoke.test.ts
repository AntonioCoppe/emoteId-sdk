import { describe, expect, it, vi } from "vitest";
import nacl from "tweetnacl";
import { createDemoWalletClient, verifyAndAttest } from "../src/index";

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
});
