# `@emoteai/sas-biometric`

Client SDK for issuing and verifying EmoteID SAS attestations and Trust Fabric credentials.

`@emoteai/sas-biometric` is the public integration layer for EmoteID. It gives dApps, wallets, agents, and institutional verifier flows a small client surface for:

- starting a biometric verification session against an issuer
- signing the issuer challenge with a wallet
- receiving a SAS attestation PDA
- completing signed api.emote.ai liveness evidence flows
- verifying the resulting attestation against wallet and policy constraints
- starting v2 trust sessions for SAS, W3C VC, SD-JWT, and signed JSON credentials
- binding wallet sessions to passkeys through WebAuthn assertion helpers

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
- `verifyAndIssueTrustCredential(options)`
- `startTrustSession(options)`
- `completeTrustSession(started, options)`
- `verifyTrustCredentialStatus(options)`
- `revokeTrustCredential(options)`
- `getPasskeyAssertion(options)`
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

## `captureSummaryProvider` Example

```ts
const result = await verifyAndAttest(userWallet, {
  issuerBaseUrl: "https://your-issuer.example.com",
  attestationKind: "session-pass",
  walletClient,
  captureSummaryProvider: async ({ sessionId, providerSessionId }) => ({
    durationSeconds: 14,
    framesProcessed: 420,
    liveness: 0.93,
    gestureConfidence: 0.91,
    hrv: 0.58,
    fatigue: 0.19,
    bpm: 72,
    gestureCode: 1,
  }),
});

console.log(result.attestationPda, sessionId, providerSessionId);
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
    minGestureConfidenceBps: 8500,
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
    minGestureConfidenceBps?: number;
    maxFatigueBucket?: number;
    minHrvBucket?: number;
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
    gestureConfidence?: number;
    hrv?: number;
    fatigue?: number;
    bpm?: number;
    gestureCode?: number;
  } | undefined>;
};
```

For the current Emote-backed flow, `gestureCode: 1` represents the completed randomized challenge. The older `bodyPose`, `patternConfidence`, and `patternCode` names remain compatibility aliases for legacy v1 integrations.

## Trust Fabric v2

```ts
import { getPasskeyAssertion, verifyAndIssueTrustCredential } from "@emoteai/sas-biometric";

const result = await verifyAndIssueTrustCredential({
  issuerBaseUrl: "https://your-issuer.example.com",
  subject: {
    type: "wallet",
    wallet: userWallet,
  },
  requestedOutputs: ["sas", "w3c-vc", "sd-jwt"],
  walletClient,
  livenessResultProvider: async ({ started }) => {
    // Render/stream started.emoteChallenge through Emote API, then return its signed result token.
    return completeEmoteChallenge(started.emoteChallenge);
  },
  passkeyAssertionProvider: (options) => (options ? getPasskeyAssertion(options) : undefined),
});

console.log(result.assuranceLevel);
console.log(result.credentials);
```

The v2 flow expects issuer endpoints:

- `POST /api/v2/trust-sessions`
- `POST /api/v2/trust-sessions/:id/complete`
- `GET /api/v2/credentials/:id/status`
- `POST /api/v2/credentials/:id/revoke`

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

- browser/client SDK: production-shaped v2 prerelease
- package: `0.2.0-hackathon.1`
- issuer integration: expected to be hosted separately
- mobile wallet path: depends on your wallet stack and platform

## GitHub Autopublish

This repo includes `.github/workflows/publish-npm.yml` for automated npm publishes from GitHub Actions.

Recommended setup:

- use npm trusted publishing instead of a long-lived `NPM_TOKEN`
- configure npm to trust the `AntonioCoppe/emoteId-sdk` repository and the `publish-npm.yml` workflow
- publish by either:
  - creating a GitHub release
  - pushing a tag like `v0.2.0-hackathon.1`
  - running the workflow manually from the Actions tab

The workflow:

- installs with `pnpm`
- runs tests
- builds the package
- skips if that exact version is already on npm
- publishes with provenance enabled
- routes `*-hackathon.*` prereleases to the npm `hackathon` dist-tag instead of `latest`

## Repository

- Source: [github.com/AntonioCoppe/emoteId-sdk](https://github.com/AntonioCoppe/emoteId-sdk)
- Demo app: [github.com/AntonioCoppe/emoteId-demo](https://github.com/AntonioCoppe/emoteId-demo)

## License

MIT
