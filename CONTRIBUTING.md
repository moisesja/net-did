# Contributing to NetDid

Thank you for your interest in contributing to NetDid. This guide covers everything you need to get started.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Git
- An editor with C# support (Visual Studio, VS Code with C# Dev Kit, Rider)

## Getting Started

```bash
# Clone the repository
git clone https://github.com/moisesja/netdid.git
cd netdid

# Build
dotnet build

# Run tests
dotnet test
```

All unit tests should pass with zero warnings.

## Working with Claude Code

If you use Claude Code, this repo ships workflow skills in `.claude/skills/` that automate the common flows — `net-did-fix` (issue/bug cycle), `net-did-verify` (the build/test/conformance "done" gate), `net-did-release` (version + NuGet publish), `adversarial-review` (security red-team pass), and `spec-conformance-audit`. See [`AGENTS.md`](AGENTS.md) for how they map to the project's principles. The accumulated do/don't rules live in [`tasks/lessons.md`](tasks/lessons.md).

## Project Structure

```
netdid/
├── src/
│   ├── NetDid.Core/                         # Core abstractions, DID model, encoding, serialization
│   │   ├── Encoding/                        # Multibase, multicodec, Base58Btc, Base64Url
│   │   ├── Exceptions/                      # Custom exception hierarchy (8 types)
│   │   ├── Model/                           # DID Document model, builder, result/option types
│   │   ├── Parsing/                         # DID string validation and URL parsing
│   │   ├── Resolution/                      # Composite resolver, caching, URL dereferencing
│   │   └── Serialization/                   # DID Document JSON/JSON-LD serializer
│   ├── NetDid.Method.Key/                   # did:key method
│   ├── NetDid.Method.Peer/                  # did:peer method (numalgo 0, 2, 4)
│   ├── NetDid.Method.WebVh/                 # did:webvh method (full CRUD)
│   └── NetDid.Extensions.DependencyInjection/  # Microsoft DI integration
├── tests/
│   ├── NetDid.Core.Tests/                   # Core unit tests (mirrors src/ structure)
│   ├── NetDid.Method.Key.Tests/
│   ├── NetDid.Method.Peer.Tests/
│   ├── NetDid.Method.WebVh.Tests/
│   ├── NetDid.Tests.W3CConformance/         # W3C DID Core conformance tests
│   └── NetDid.Extensions.DependencyInjection.Tests/
├── samples/
│   ├── NetDid.Samples.DidKey/               # did:key usage examples
│   ├── NetDid.Samples.DidPeer/              # did:peer usage examples
│   ├── NetDid.Samples.DidWebVh/             # did:webvh CRUD examples
│   └── NetDid.Samples.DependencyInjection/  # DI registration pattern
├── Directory.Build.props                    # Shared build properties
├── Directory.Packages.props                 # Central NuGet version management
├── .editorconfig                            # Code style rules
└── netdid.sln
```

## Code Style

The project uses an `.editorconfig` that enforces consistent style. Key conventions:

- **File-scoped namespaces**: `namespace Foo;` not `namespace Foo { }`
- **4-space indentation** (no tabs)
- **LF line endings**
- **UTF-8 encoding** without BOM
- **Expression-bodied members** for simple properties and accessors
- **System directives first** in using statements
- **Nullable reference types** enabled everywhere

Your editor should pick up these settings automatically from `.editorconfig`.

## Testing Conventions

Tests use **xunit** with **FluentAssertions** for assertions and **NSubstitute** for mocking.

### Test project setup

- `GlobalUsings.cs` provides `global using Xunit;` so test files don't need explicit xunit imports
- Test file structure mirrors `src/` — e.g., `src/NetDid.Core/Parsing/DidParser.cs` is tested by `tests/NetDid.Core.Tests/Parsing/DidParserTests.cs`

### Naming convention

```
MethodName_Condition_ExpectedResult
```

Examples:
```csharp
SignVerify_Ed25519_RoundTrip()
Deserialize_JsonLd_MissingContext_Throws()
GenerateAsync_DuplicateAlias_Throws()
```

### Writing tests

```csharp
using FluentAssertions;
using NetDid.Core.Crypto;

namespace NetDid.Core.Tests.Crypto;

public class MyFeatureTests
{
    [Fact]
    public void MyMethod_ValidInput_ReturnsExpectedResult()
    {
        // Arrange
        var sut = new MyClass();

        // Act
        var result = sut.MyMethod("input");

        // Assert
        result.Should().Be("expected");
    }
}
```

### Running specific tests

```bash
# Run a single test class
dotnet test --filter "FullyQualifiedName~DefaultKeyGeneratorTests"

# Run a single test
dotnet test --filter "Generate_Ed25519_ProducesValidKeyPair"
```

## Package Management

NetDid uses **Central Package Management** via `Directory.Packages.props`. All NuGet version numbers are declared in this single file.

### Adding a new dependency

1. Add the version to `Directory.Packages.props`:
   ```xml
   <PackageVersion Include="My.Package" Version="1.2.3" />
   ```

2. Reference it in the relevant `.csproj` (without a version):
   ```xml
   <PackageReference Include="My.Package" />
   ```

### Updating a dependency

Change the version only in `Directory.Packages.props`. All projects referencing that package will pick up the new version.

## How to Add a New DID Method

To implement a new DID method (e.g., `did:web`):

1. **Create a new project**: `src/NetDid.Method.Web/`

2. **Define create options** with the `MethodName` override:
   ```csharp
   public sealed record DidWebCreateOptions : DidCreateOptions
   {
       public override string MethodName => "web";
       // Method-specific properties...
   }
   ```

3. **Implement `IDidMethod`** (or extend `DidMethodBase`):
   ```csharp
   public class DidWebMethod : DidMethodBase
   {
       public override string MethodName => "web";
       public override DidMethodCapabilities Capabilities =>
           DidMethodCapabilities.Create | DidMethodCapabilities.Resolve;

       // Implement the abstract Core* methods...
   }
   ```

4. **Add DI registration** in `NetDid.Extensions.DependencyInjection/NetDidBuilder.cs`:
   ```csharp
   public NetDidBuilder AddDidWeb()
   {
       Services.TryAddSingleton<DidWebMethod>();
       Services.AddSingleton<IDidMethod>(sp => sp.GetRequiredService<DidWebMethod>());
       return this;
   }
   ```

5. **Add tests** following the existing pattern in `tests/`.

6. **Add a sample project**: `samples/NetDid.Samples.DidWeb/`

7. **Update `NetDidPRD.md`** with the method's specification details.

## Cryptography lives in NetCrypto

NetDid carries **no cryptographic primitives or native code**. All key generation, signing,
verification, key agreement, JWK conversion, and the BBS+ / BLS12-381 native payloads are
provided by the [**NetCrypto**](https://www.nuget.org/packages/NetCrypto) package (the
[`crypto-dotnet`](https://github.com/moisesja/crypto-dotnet) repository), consumed via `dotnet
restore` with no manual build step. did:webvh Data Integrity proofs come from
[**DataProofsDotnet**](https://www.nuget.org/packages/DataProofsDotnet.Core). Adding a new key
type or cryptographic capability is a change in those repositories, not here — NetDid only
maps key types to multicodec prefixes (`Encoding/`) and consumes `NetCrypto.KeyType` /
`NetCrypto.ISigner` through its DID-method APIs.

## Commit Messages

Write concise commit messages that describe what changed and why:

```
Add did:peer numalgo 4 long-form resolution

Resolve the long-form did:peer:4 identifier by decoding the
multibase-encoded document and verifying the embedded SCID hash.
```

- Use imperative mood ("Add", "Fix", "Update")
- First line: summary under 72 characters
- Optional body: explain the "why" if not obvious

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Make your changes, ensuring all tests pass (`dotnet test`)
3. Ensure the build has zero warnings (`dotnet build`)
4. Write tests for any new functionality
5. Submit a PR with a clear description of what you changed and why

## W3C Conformance

NetDid targets 100% compliance with the [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) specification. When making changes to the DID Document model or serialization:

- Verify DID Documents comply with DID Core production rules (section 6)
- JSON-LD representations must include valid `@context`
- Plain JSON representations must not require `@context`
- All verification relationship entries support both string references and embedded objects
- `controller` serializes as a string when one value, array when multiple

See [NetDidPRD.md](NetDidPRD.md) for the full requirements specification.

## AI-Assisted Workflows

This project supports AI-assisted development. See [AGENTS.md](AGENTS.md) for instructions on using AI agents with this codebase, including plan mode requirements, subagent strategy, and verification procedures.

## Questions?

Open an issue on GitHub if you have questions or want to discuss a potential contribution before starting work.
