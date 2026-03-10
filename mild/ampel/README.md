# Mild: AMPEL

Presence, signer identity, and SLSA level checks using [AMPEL](https://github.com/carabiner-dev/ampel).

## What This Checks

1. **Provenance present** -- a SLSA provenance attestation is attached
2. **Signer identity** -- the attestation was signed by the expected GitHub Actions workflow (via Sigstore identity verification)
3. **SLSA level** -- a VSA declares at least `SLSA_BUILD_LEVEL_1`

## Running

```bash
ampel verify <IMAGE_REF> \
  --policy ./policy.hjson
```

See the [AMPEL project](https://github.com/carabiner-dev/ampel) for full usage.
