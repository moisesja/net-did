# webvh-cli

A step-by-step CLI tool for creating and managing **did:webvh** Decentralized Identifiers. It walks through the full DID creation process one command at a time — ideal for learning, demos, and manual DID management.

Built on the [NetDid](../../README.md) library.

## Installation

```bash
# Install as a global .NET tool
dotnet tool install --global NetDid.Tools.WebVhCli

# Or run from the repository
dotnet run --project tools/NetDid.Tools.WebVhCli -- <command> [options]
```

## Quick Start

Create a did:webvh DID in 9 steps:

```bash
# 1. Generate an Ed25519 key pair
webvh-cli new-key --name update-key --output-dir ./my-did

# 2. Initialize the DID workflow
webvh-cli new-did --domain example.com --update-key update-key --output-dir ./my-did

# 3. Set DID parameters
webvh-cli did-params --ttl 86400 --output-dir ./my-did

# 4. Build the genesis log entry template
webvh-cli gen-scid-input --output-dir ./my-did

# 5. Compute the SCID
webvh-cli gen-scid-value --output-dir ./my-did

# 6. Compute the version ID
webvh-cli gen-version-id --output-dir ./my-did

# 7. Add a verification method (optional — the update key is included by default)
webvh-cli add-vm --key update-key --relationship authentication --output-dir ./my-did

# 8. Sign the log entry
webvh-cli add-proof --key update-key --output-dir ./my-did

# 9. Write the log files
webvh-cli new-line --output-dir ./my-did
```

This produces two artifacts in `./my-did/`:
- **`did.jsonl`** — the did:webvh verifiable history log
- **`did.json`** — the did:web compatible DID Document

## Commands

### `new-key` — Generate Key Pair

Generates an Ed25519 key pair and stores it in `key-store.json`.

```
webvh-cli new-key --name <key-name> [--output-dir <dir>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--name` | Yes | Name to identify the key pair |
| `--output-dir` | No | Directory for state files (default: `.`) |

**Output:**
```
Key generated: update-key
  Multibase public key: z6MksfBsqN...
  did:key DID:          did:key:z6MksfBsqN...
  Saved to:             ./my-did/key-store.json
```

You can generate multiple keys for different purposes (update key, next key for pre-rotation, additional verification methods).

### `new-did` — Initialize Workflow

Starts a new DID creation workflow. If a `did.jsonl` already exists in the output directory, the tool automatically enters **update mode**.

```
webvh-cli new-did --domain <domain> --update-key <key-name> [--path <path>] [--output-dir <dir>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--domain` | Yes | Domain for the DID (e.g., `example.com`) |
| `--update-key` | Yes | Name of the key to use as the update key |
| `--path` | No | Optional path segment (e.g., `users/alice`) |
| `--output-dir` | No | Directory for state files (default: `.`) |

### `did-params` — Set Parameters

Configures the DID parameters for the current workflow.

```
webvh-cli did-params [--prerotation] [--portable] [--ttl <seconds>] [--next-key <key-name>] [--output-dir <dir>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--prerotation` | No | Enable pre-rotation key commitment |
| `--portable` | No | Enable DID portability |
| `--ttl` | No | Time-to-live in seconds |
| `--next-key` | If `--prerotation` | Name of the next key for pre-rotation commitment |
| `--output-dir` | No | Directory for state files (default: `.`) |

### `gen-scid-input` — Generate SCID Input

Builds the genesis log entry template with `{SCID}` placeholders. In update mode, builds the update entry with a temporary version ID.

```
webvh-cli gen-scid-input [--output-dir <dir>]
```

### `gen-scid-value` — Compute SCID

Computes the Self-Certifying Identifier from the genesis log entry template using the two-pass algorithm: JCS-canonicalize, SHA-256 hash, multibase encode. In update mode, this step is a pass-through since the SCID is fixed at creation.

```
webvh-cli gen-scid-value [--output-dir <dir>]
```

**Output:**
```
SCID computed:
  SCID: z6Qf9TzingiBJ8Y5DUykqc4dWHsJKbJoz9Frd4wBSsCPXF
  DID:  did:webvh:z6Qf9TzingiBJ8Y5DUykqc4dWHsJKbJoz9Frd4wBSsCPXF:example.com
```

### `gen-version-id` — Compute Version ID

Computes the version ID and entry hash. For genesis entries, the version ID is `1-{SCID}`. For update entries, it computes the entry hash from the log entry JSON.

```
webvh-cli gen-version-id [--output-dir <dir>]
```

### `add-vm` — Add Verification Method

Adds a verification method to the DID Document and registers it under the specified relationship. Can be called multiple times to add multiple VMs.

```
webvh-cli add-vm --key <key-name> --relationship <relationship> [--output-dir <dir>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--key` | Yes | Name of the key to add |
| `--relationship` | Yes | One of: `authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityDelegation` |
| `--output-dir` | No | Directory for state files (default: `.`) |

> **Note**: The update key is automatically included as a verification method during genesis. Duplicate references are prevented automatically.

### `add-proof` — Sign Log Entry

Signs the log entry using a Data Integrity Proof (eddsa-jcs-2022 cryptosuite).

```
webvh-cli add-proof --key <key-name> [--output-dir <dir>]
```

| Option | Required | Description |
|--------|----------|-------------|
| `--key` | Yes | Name of the signing key (must be the update key or an authorized key) |
| `--output-dir` | No | Directory for state files (default: `.`) |

### `new-line` — Write Log Line

Writes the finalized, signed log entry to `did.jsonl` and generates `did.json` for did:web compatibility. In update mode, the new entry is appended to existing entries.

```
webvh-cli new-line [--output-dir <dir>]
```

**Output:**
```
Log line written:
  DID:         did:webvh:z6Qf9Tzi...:example.com
  Version:     1-z6Qf9Tzi...
  did.jsonl:   /path/to/did.jsonl
  did.json:    /path/to/did.json
  Entries:     1
```

## Workflow

### Create Flow

The 9 commands form a sequential pipeline. Each command advances the workflow state and validates that the previous step was completed:

```
new-key → new-did → did-params → gen-scid-input → gen-scid-value → gen-version-id → add-vm* → add-proof → new-line
```

`*` = optional, can be called multiple times

### Update Flow

To update an existing DID, run the same sequence in a directory that already contains `did.jsonl`. The tool automatically detects update mode:

```bash
# Generate a new key (if rotating)
webvh-cli new-key --name new-update-key --output-dir ./my-did

# Start update workflow — detects existing did.jsonl
webvh-cli new-did --domain example.com --update-key new-update-key --output-dir ./my-did

# Continue with the same steps...
webvh-cli did-params --output-dir ./my-did
webvh-cli gen-scid-input --output-dir ./my-did
webvh-cli gen-scid-value --output-dir ./my-did
webvh-cli gen-version-id --output-dir ./my-did
webvh-cli add-proof --key new-update-key --output-dir ./my-did
webvh-cli new-line --output-dir ./my-did
```

### Pre-Rotation

To enable pre-rotation, generate a next key and pass it during parameter setup:

```bash
webvh-cli new-key --name next-key --output-dir ./my-did
webvh-cli did-params --prerotation --next-key next-key --output-dir ./my-did
```

The tool computes the key commitment hash automatically using `SHA-256(multibase-public-key)`.

## State Files

All state is persisted in the output directory:

| File | Purpose |
|------|---------|
| `key-store.json` | Named key pairs (public + private key material) |
| `working-state.json` | Current workflow phase and intermediate state |
| `did.jsonl` | Produced artifact: the did:webvh verifiable history log |
| `did.json` | Produced artifact: did:web compatible DID Document |

> **Security**: `key-store.json` contains private key material. Protect it accordingly — do not commit it to version control or share it publicly.

## Related

- [NetDid README](../../README.md) — main library documentation
- [did:webvh specification](https://www.w3.org/TR/did-webvh/) — W3C specification
- [W3C Conformance Report](../../w3c-conformance-report.md) — test results
