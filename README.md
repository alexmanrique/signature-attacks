## Signature Attacks

Exercise to study signature attacks in Solidity contracts. It includes a
vulnerable version and a secure version, plus Foundry tests that show the
expected behavior.

## Contracts

- `SignatureAttacks.sol` → `VulnerableSignatureContract`
  - Uses `ecrecover` without validating the result.
  - Allows invalid signatures (that return `address(0)`) to authorize users.
  - Includes basic replay protection with `usedHashes`.
- `SecureSignatureContract.sol` → `SecureSignatureContract`
  - Validates that `ecrecover` does not return `address(0)`.
  - Includes an alternative version with `v` and `s` validation (anti-malleability).
  - Keeps replay protection with `usedHashes`.

## Tests

- `test/SignatureAttacks.t.sol`
  - Shows that the vulnerable version accepts invalid or malformed signatures.
- `test/SecureSignatureAttacks.t.sol`
  - Verifies the secure version reverts on invalid signatures and prevents replay.


