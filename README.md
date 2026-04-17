# `@emoteai/sas-biometric`

Thin client SDK for issuing and verifying EmoteID biometric attestations on Solana.

`@emoteai/sas-biometric` is the public integration layer for EmoteID. It gives dApps, wallets, agents, and trading flows a small client surface for:

- starting a biometric verification session against an issuer
- signing the issuer challenge with a wallet
- receiving a SAS attestation PDA
- verifying the resulting attestation against wallet and policy constraints

This package is intentionally thin. It does not embed secrets, issue attestations directly from the browser, or replace your backend issuer.

## Install

```bash
npm install @emoteai/sas-biometric
```

Peer/runtime expectations:

- `react` is required because the package exports `useEmoteID`
- `react-dom` is a peer dependency
- if you only use the non-React helpers, you can ignore the hook and call `verifyAndAttest` directly

## What It Exports

- `verifyAndAttest(wallet, options)`
- `verifyAttestation(rpc, input)`
- `useEmoteID(options)`
- `createDemoWalletClient(seed?)`

## Quick Start

```ts
import { verifyAndAttest } from "@emoteai/sas-biometric";

const result = await verifyAndAttest(userWallet, {
  issuerBaseUrl: "https://your-issuer.example.com",
  attestationKind: "session-pass",
  sessionDurationSeconds: 60 * 60 * 4,
  maxX402Calls: 1000,
  walletClient: {
    async signMessage(message) {
      return walletAdapter.signMessage(message);
    },
  },
});

console.log(result.attestationPda);
console.log(result.txSignature);
```

## React Hook

```tsx
import { useEmoteID } from "@emoteai/sas-biometric";

export function VerifyButton({
  wallet,
  walletClient,
}: {
  wallet: string;
  walletClient: { signMessage(message: Uint8Array): Promise<Uint8Array> } | null;
}) {
  const emote = useEmoteID({
    issuerBaseUrl: "https://your-issuer.example.com",
    attestationKind: "single-action",
    walletClient,
  });

  return (
    <button disabled={!walletClient || emote.loading} onClick={() => emote.verify(wallet)}>
      {emote.loading ? "Verifying..." : "Verify with EmoteID"}
    </button>
  );
}
```

## Verifying An Attestation

`verifyAttestation` checks:

- attestation existence
- wallet match
- expiry
- threshold policy

If the attestation payload is in the full SAS schema format, the helper will fetch and decode the schema account automatically from the RPC adapter you provide.

```ts
import { verifyAttestation } from "@emoteai/sas-biometric";

const verification = await verifyAttestation(rpc, {
  attestationPda,
  wallet: userWallet,
  policy: {
    minLivenessBps: 9000,
    minBodyPoseBps: 8500,
  },
});

if (!verification.valid) {
  console.error(verification.reasons);
}
```

## Issuer Contract

The SDK expects an issuer with these endpoints:

- `POST /api/v1/verification-sessions`
- `POST /api/v1/verification-sessions/:id/complete`

Expected flow:

1. client asks issuer to create a verification session
2. issuer returns a wallet challenge
3. client signs the challenge
4. client optionally sends capture summary telemetry
5. issuer completes the biometric evaluation and issues a SAS attestation
6. client receives `attestationPda` and transaction metadata

## `verifyAndAttest` Options

```ts
type VerifyAndAttestOptions = {
  issuerBaseUrl: string;
  attestationKind?: "single-action" | "session-pass";
  sessionDurationSeconds?: number;
  maxX402Calls?: number;
  expirySeconds?: number;
  policy?: {
    minLivenessBps?: number;
    minBodyPoseBps?: number;
    maxFatigueBucket?: number;
    minHrvBucket?: number;
    requiredPatternCode?: number;
    requiredGestureCode?: number;
  };
  controllerWallet?: string;
  walletClient: {
    signMessage(message: Uint8Array): Promise<Uint8Array>;
  };
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
};
```

For the current Emote-backed flow, `patternCode: 1` represents the `angry -> happy -> sad` expression sequence. The older `gestureCode` and `bodyPose` names remain as compatibility aliases for the v1 schema.

## Security Notes

- Do not put Emote API keys or SAS signing keys in browser code.
- The issuer must validate wallet signatures server-side.
- The client SDK is only an orchestration layer. Trust and issuance live on the issuer and on chain.
- For production, use short expiries for sensitive actions and tighter policies for treasury or agent spend.

## Intended Use Cases

- verified swaps and launch participation
- high-value wallet or treasury actions
- agent spend gates
- human-in-the-loop x402 payment sessions

## Status

Current package version:

- browser/client SDK: production-shaped
- issuer integration: expected to be hosted separately
- mobile wallet path: depends on your wallet stack and platform

## Repository

- Monorepo: [github.com/emoteai/emoteid](https://github.com/emoteai/emoteid)

## License

MIT
