# Paying an x402 route as a client

Last checked against `gosuda/portal-tunnel` main commit `d38001adc0ed1c0c9962a0628c8a2cd348d57dfa` and `github.com/gosuda/x402-facilitator` `v0.0.5-0.20260918144508-4423ff00e0f5` on 2026-09-22. Prefer the live `402` challenge over anything written here.

## Two x402 surfaces

- The paid route belongs to the publisher's tunnel process. The challenge, `POST /x402/prepare`, and `GET /x402/client.js` are served on the service's own origin (`https://<name>.<relay-host>`), with no `/api` prefix.
- `GET <relay>/api/x402/*` is a relay-owned facilitator for relay resources. It never settles a tunnel route. Do not send a tunnel payment there.

## Wire headers

| Header | Direction | Role |
|--------|-----------|------|
| `PAYMENT-REQUIRED`, `X-PAYMENT-REQUIRED` | response | base64 copy of the 402 challenge body |
| `PAYMENT-SIGNATURE` | request | canonical v2 payment payload |
| `X-PAYMENT` | request | legacy name for the same payload; accepted when the canonical header is absent |
| `PAYMENT-RESPONSE`, `X-PAYMENT-RESPONSE` | response | base64 settlement receipt on success, and on a structured settlement failure |

The payload value may be raw JSON or base64 (standard or URL alphabet, padded or not). Use standard base64 for predictability.

## The 402 challenge

Status `402`, `Content-Type: application/json`, `Cache-Control: no-store`:

```json
{
  "x402Version": 2,
  "error": "payment required",
  "resource": { "url": "https://paid-app.portal.example.com/paid", "description": "", "mimeType": "" },
  "accepts": [
    {
      "scheme": "exact",
      "network": "sui:testnet",
      "asset": "0x...::usdc::USDC",
      "amount": "10000",
      "payTo": "0x...",
      "maxTimeoutSeconds": 60,
      "extra": { "paymentFlow": "upfront" }
    }
  ]
}
```

`error` is one of `payment required`, `invalid payment payload`, `payment requirements mismatch`, or `payment settlement failed`. Only the first means "not paid yet".

`amount` is an integer string in atomic units:

| Network | Asset | Decimals | Example |
|---------|-------|----------|---------|
| `sui:mainnet`, `sui:testnet` | USDC | 6 | `"10000"` = 0.01 USDC |
| `casper:casper`, `casper:casper-test` | wCSPR (CEP-18) | 9 | `"10000000"` = 0.01 wCSPR |

Portal always publishes `extra.paymentFlow` as `"upfront"`: the payment settles before the resource runs, and one payment covers one request.

## Before signing anything

Show the user, and get an explicit yes for this request:

- human amount and asset, and whether the network is mainnet or testnet
- recipient (`payTo`)
- the exact method and URL the payment unlocks (`resource.url`)
- that a repeated request will be charged again

Never ask for or print a private key, seed phrase, or keystore file. Signing happens inside the user's wallet tooling; you only move unsigned bytes in and a signature out.

## Sui flow (USDC)

1. Capture the challenge:

   ```sh
   curl -sS --connect-timeout 5 --max-time 15 -D /tmp/x402-headers -o /tmp/x402-challenge.json \
     https://paid-app.portal.example.com/paid
   jq '.accepts[0]' /tmp/x402-challenge.json
   ```

2. Ask the route to build the unsigned transaction for the payer's address. `path` is required, `method` defaults to `GET`:

   ```sh
   curl -sS --connect-timeout 5 --max-time 15 -X POST \
     -H 'Content-Type: application/json' \
     -d '{"sender":"0x<payer-sui-address>","method":"GET","path":"/paid"}' \
     https://paid-app.portal.example.com/x402/prepare -o /tmp/x402-prepare.json
   ```

   Response:

   ```json
   {
     "x402Version": 2,
     "paymentRequirements": { "...": "same shape as accepts[0]" },
     "resource": { "url": "...", "description": "", "mimeType": "" },
     "paymentTransaction": { "transaction": "<base64 unsigned Sui TransactionData>" },
     "prepareTransaction": { "transaction": "<base64>" }
   }
   ```

   `404` means the path or method is not paid. `prepareTransaction` is optional; when present the payer's USDC objects must be consolidated first: sign and execute that transaction with the wallet, then repeat this step until the field disappears (the browser helper polls up to 20 times, one second apart).

3. Sign `paymentTransaction.transaction` with the user's Sui wallet without altering the bytes. Options, in the user's hands:

   - the `sui` CLI keystore, for example `sui keytool sign --address 0x<payer> --data <base64> --json` and read the signature field (check `sui keytool sign --help` for the installed version)
   - a small script with `@mysten/sui` and the user's own key management

   The gate rejects a payment whose transaction bytes differ from what it prepared, so do not re-serialize or "fix" the transaction.

4. Build the payload and send it:

   ```sh
   jq -n --arg sig "<signature>" --slurpfile p /tmp/x402-prepare.json '{
     x402Version: 2,
     payload: { signature: $sig, transaction: $p[0].paymentTransaction.transaction },
     accepted: $p[0].paymentRequirements,
     resource: $p[0].resource
   }' | base64 | tr -d '\n' > /tmp/x402-payment.b64

   curl -sS --connect-timeout 5 --max-time 60 -D /tmp/x402-paid-headers \
     -H "X-PAYMENT: $(cat /tmp/x402-payment.b64)" \
     https://paid-app.portal.example.com/paid
   ```

   `accepted` must be the `paymentRequirements` object from the prepare response, verbatim, including `extra`. The gate compares scheme, network, asset, amount, recipient, timeout, and every server-declared `extra` key; any drift returns `402` with `payment requirements mismatch`.

5. Read the receipt. `PAYMENT-RESPONSE` (mirrored in `X-PAYMENT-RESPONSE`) is base64 JSON:

   ```json
   { "success": true, "transaction": "<on-chain transaction id>", "network": "sui:testnet", "payer": "0x<payer>" }
   ```

   On failure `success` is false and `errorReason` / `errorMessage` explain why. Report `transaction`, `network`, and `payer`. The `--max-time` in step 4 is longer than usual because settlement waits for chain confirmation, bounded by `maxTimeoutSeconds`.

## Casper flow (wCSPR)

There is no server-built transaction. `POST /x402/prepare` answers with the same 402 challenge JSON instead of a transaction. Sign the published requirements with the user's Casper x402 SDK or wallet, then retry the request with `PAYMENT-SIGNATURE` (or `X-PAYMENT`) carrying the SDK's payload. Portal forwards verification and settlement to the publisher's configured Casper facilitator; nothing on the client side needs a facilitator token.

## After the retry

- `200`..`399` with `PAYMENT-RESPONSE`: paid and served. Delete any temporary files holding the payload.
- `402` `payment requirements mismatch`: the `accepted` object drifted, or the publisher changed the route contract since the challenge. Do not re-sign on your own; refetch the challenge and re-confirm the new terms with the user.
- `402` `payment settlement failed` with a receipt: the facilitator could not settle. Funds may or may not have moved. Report the receipt to the user; do not retry automatically.
- `402` `invalid payment payload`: encoding problem on the client side. Rebuild the payload from the prepare response before asking the user to sign again.

## Rules

- Never spend to verify. An unpaid request that returns `402` with the expected `network`, `asset`, `amount`, `payTo`, and `resource.url` is the whole check.
- A signed payload is a spend authorization. Do not reuse it, log it, or leave it in a file.
- A testnet route costs test tokens only, but the approval step is the same: the user still decides.
