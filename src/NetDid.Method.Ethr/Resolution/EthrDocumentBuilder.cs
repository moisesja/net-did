using NetCid;
using NetDid.Core.Crypto;
using NetDid.Core.Jwk;
using NetDid.Core.Model;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Erc1056;
using static NetDid.Method.Ethr.Crypto.EthereumAddress;

namespace NetDid.Method.Ethr.Resolution;

/// <summary>
/// Builds a W3C DID Document from a list of ERC-1056 events.
/// Called by DidEthrMethod.ResolveCoreAsync after collecting the event chain.
/// </summary>
public static class EthrDocumentBuilder
{
    // Well-known @context URLs
    private const string DidV1Context       = "https://www.w3.org/ns/did/v1";
    private const string Secp256k1Recovery  = "https://w3id.org/security/suites/secp256k1recovery-2020/v2";
    private const string SecurityV2         = "https://w3id.org/security/v2";
    private const string Ed25519_2020       = "https://w3id.org/security/suites/ed25519-2020/v1";
    private const string X25519_2020        = "https://w3id.org/security/suites/x25519-2020/v1";
    private const string MultikeyCtx        = "https://w3id.org/security/multikey/v1";

    private const string ZeroAddress        = "0x0000000000000000000000000000000000000000";

    public static DidDocument Build(
        string did,
        EthrIdentifier identifier,
        string chainId,
        IReadOnlyList<Erc1056Event> events,
        DateTimeOffset referenceTime,
        bool isDeactivated)
    {
        var refUnix = (ulong)referenceTime.ToUnixTimeSeconds();

        // ── Replay events (JS-compatible: last-event-wins per logical key) ─────
        //
        // The JS ethr-did-resolver keys entries by (eventName, name/delegateType, value/delegate)
        // and ALWAYS increments the delegate/service counter — even for expired events.
        // Expired events DELETE any previously-added entry for the same key, so a later
        // revocation removes an earlier valid entry and a re-registration gets a new ID.
        string currentOwner = identifier.IdentityAddress;
        int delegateCount = 0;
        int serviceCount  = 0;

        // Key: eventIndex string → (counter, entry).  Keyed by (eventName-name-value).
        var delegates  = new Dictionary<string, (int Counter, DelegateEntry Entry)>();
        var attributes = new Dictionary<string, (int Counter, AttributeEntry Entry)>();
        var services   = new Dictionary<string, (int Counter, ServiceEntry Entry)>();

        foreach (var ev in events)
        {
            switch (ev)
            {
                case OwnerChangedEvent oc:
                    currentOwner = oc.NewOwner;
                    break;

                case DelegateChangedEvent dc:
                {
                    delegateCount++;
                    var key = $"DIDDelegateChanged-{dc.DelegateType}-{dc.Delegate}";
                    if (dc.ValidTo >= refUnix)
                        delegates[key] = (delegateCount, new DelegateEntry(dc.DelegateType, dc.Delegate, dc.ValidTo));
                    else
                        delegates.Remove(key);
                    break;
                }

                case AttributeChangedEvent ac when ac.Name.StartsWith("did/pub/"):
                {
                    delegateCount++;
                    var key = $"DIDAttributeChanged-{ac.Name}-{Convert.ToHexString(ac.Value)}";
                    if (ac.ValidTo >= refUnix)
                        attributes[key] = (delegateCount, new AttributeEntry(ac.Name, ac.Value, ac.ValidTo));
                    else
                        attributes.Remove(key);
                    break;
                }

                case AttributeChangedEvent ac when ac.Name.StartsWith("did/svc/"):
                {
                    serviceCount++;
                    var key = $"DIDAttributeChanged-{ac.Name}-{Convert.ToHexString(ac.Value)}";
                    var svcName = ac.Name["did/svc/".Length..];
                    var svcEndpoint = System.Text.Encoding.UTF8.GetString(ac.Value);
                    if (ac.ValidTo >= refUnix)
                        services[key] = (serviceCount, new ServiceEntry(svcName, svcEndpoint, ac.ValidTo));
                    else
                        services.Remove(key);
                    break;
                }
            }
        }

        // ── Deactivation check ────────────────────────────────────────────────
        if (isDeactivated || currentOwner == ZeroAddress)
        {
            return new DidDocument
            {
                Id      = new Did(did),
                Context = BuildContext(false, false, false, false, false),
            };
        }

        // Entries are already filtered (expired ones were deleted during replay).
        var validDelegates  = delegates.Values.OrderBy(x => x.Counter).ToList();
        var validAttributes = attributes.Values.OrderBy(x => x.Counter).ToList();
        var validServices   = services.Values.OrderBy(x => x.Counter).ToList();

        // ── Build verification methods ────────────────────────────────────────
        var vms      = new List<VerificationMethod>();
        var auths    = new List<VerificationRelationshipEntry>();
        var asserts  = new List<VerificationRelationshipEntry>();
        var keyAgree = new List<VerificationRelationshipEntry>();

        // Flags for @context
        bool needsSecp256k1Key = false, needsEd25519 = false,
             needsX25519 = false, needsMultikey = false, needsHex = false;

        // #controller — always present
        var controllerVmId = $"{did}#controller";
        vms.Add(new VerificationMethod
        {
            Id                 = controllerVmId,
            Type               = "EcdsaSecp256k1RecoveryMethod2020",
            Controller         = new Did(did),
            BlockchainAccountId = $"eip155:{chainId}:{Checksum(currentOwner)}",
        });
        auths.Add(VerificationRelationshipEntry.FromReference(controllerVmId));
        asserts.Add(VerificationRelationshipEntry.FromReference(controllerVmId));

        // #controllerKey — only when DID encodes a public key AND owner hasn't changed away
        if (identifier.IsPublicKey && identifier.PublicKeyBytes is not null
            && string.Equals(currentOwner, identifier.IdentityAddress, StringComparison.OrdinalIgnoreCase))
        {
            needsSecp256k1Key = true;
            var ckId = $"{did}#controllerKey";
            vms.Add(new VerificationMethod
            {
                Id           = ckId,
                Type         = "EcdsaSecp256k1VerificationKey2019",
                Controller   = new Did(did),
                PublicKeyJwk = JwkConverter.ToPublicJwk(KeyType.Secp256k1, identifier.PublicKeyBytes),
            });
            auths.Add(VerificationRelationshipEntry.FromReference(ckId));
            asserts.Add(VerificationRelationshipEntry.FromReference(ckId));
        }

        // Delegate-based VMs (#delegate-N)
        foreach (var (counter, d) in validDelegates)
        {
            var vmId = $"{did}#delegate-{counter}";
            vms.Add(new VerificationMethod
            {
                Id                  = vmId,
                Type                = "EcdsaSecp256k1RecoveryMethod2020",
                Controller          = new Did(did),
                BlockchainAccountId = $"eip155:{chainId}:{Checksum(d.DelegateAddress)}",
            });
            var rel = VerificationRelationshipEntry.FromReference(vmId);
            if (d.DelegateType == "sigAuth") auths.Add(rel);
            else asserts.Add(rel); // veriKey and unknown → assertionMethod
        }

        // Attribute-based key VMs (#delegate-N)
        foreach (var (counter, a) in validAttributes)
        {
            // Parse: did/pub/{algorithm}/{purpose}/{encoding?}
            var parts    = a.Name.Split('/');
            var algorithm = parts.Length > 2 ? parts[2] : "unknown";
            var purpose   = parts.Length > 3 ? parts[3] : "veriKey";
            var vmId      = $"{did}#delegate-{counter}";

            VerificationMethod? vm = null;
            switch (algorithm)
            {
                case "Secp256k1":
                    needsSecp256k1Key = true;
                    vm = new VerificationMethod
                    {
                        Id           = vmId,
                        Type         = "EcdsaSecp256k1VerificationKey2019",
                        Controller   = new Did(did),
                        PublicKeyJwk = JwkConverter.ToPublicJwk(KeyType.Secp256k1, a.Value),
                    };
                    break;

                case "Ed25519":
                    needsEd25519 = true;
                    vm = new VerificationMethod
                    {
                        Id                   = vmId,
                        Type                 = "Ed25519VerificationKey2020",
                        Controller           = new Did(did),
                        PublicKeyMultibase   = EncodeMultibase(a.Value, KeyType.Ed25519),
                    };
                    break;

                case "X25519":
                    needsX25519 = true;
                    vm = new VerificationMethod
                    {
                        Id                   = vmId,
                        Type                 = "X25519KeyAgreementKey2020",
                        Controller           = new Did(did),
                        PublicKeyMultibase   = EncodeMultibase(a.Value, KeyType.X25519),
                    };
                    break;

                case "Multikey":
                    needsMultikey = true;
                    vm = new VerificationMethod
                    {
                        Id                   = vmId,
                        Type                 = "Multikey",
                        Controller           = new Did(did),
                        PublicKeyMultibase   = EncodeMultibaseRaw(a.Value),
                    };
                    break;

                default:
                    needsHex = true;
                    // Store raw hex in AdditionalProperties under publicKeyHex
                    var hexDict = new Dictionary<string, System.Text.Json.JsonElement>
                    {
                        ["publicKeyHex"] = System.Text.Json.JsonSerializer.SerializeToElement(
                            Convert.ToHexString(a.Value).ToLowerInvariant())
                    };
                    vm = new VerificationMethod
                    {
                        Id                   = vmId,
                        Type                 = algorithm,
                        Controller           = new Did(did),
                        AdditionalProperties = hexDict,
                    };
                    break;
            }

            if (vm is null) continue;
            vms.Add(vm);
            var rel = VerificationRelationshipEntry.FromReference(vmId);
            if (purpose == "enc")       keyAgree.Add(rel);
            else if (purpose == "sigAuth") auths.Add(rel);
            else                        asserts.Add(rel); // veriKey default
        }

        // Services
        var svcList = validServices.Select(kv => new Service
        {
            Id              = $"{did}#service-{kv.Counter}",
            Type            = kv.Entry.ServiceName,
            ServiceEndpoint = ServiceEndpointValue.FromUri(kv.Entry.Endpoint),
        }).ToList();

        return new DidDocument
        {
            Id                 = new Did(did),
            VerificationMethod = vms,
            Authentication     = auths,
            AssertionMethod    = asserts,
            KeyAgreement       = keyAgree.Count > 0 ? keyAgree : null,
            Service            = svcList.Count > 0 ? svcList : null,
            Context            = BuildContext(needsSecp256k1Key, needsEd25519, needsX25519,
                                              needsMultikey, needsHex),
        };
    }

    // ── Context builder ───────────────────────────────────────────────────────

    private static IReadOnlyList<object> BuildContext(
        bool secp256k1Key, bool ed25519, bool x25519, bool multikey, bool hex)
    {
        var ctx = new List<object> { DidV1Context, Secp256k1Recovery };
        if (secp256k1Key)
        {
            ctx.Add(SecurityV2);
            ctx.Add(System.Text.Json.JsonSerializer.SerializeToElement(new Dictionary<string, object>
            {
                ["publicKeyJwk"] = new Dictionary<string, string>
                {
                    ["@id"]   = "https://w3id.org/security#publicKeyJwk",
                    ["@type"] = "@json"
                }
            }));
        }
        if (ed25519)   ctx.Add(Ed25519_2020);
        if (x25519)    ctx.Add(X25519_2020);
        if (multikey)  ctx.Add(MultikeyCtx);
        if (hex)       ctx.Add(System.Text.Json.JsonSerializer.SerializeToElement(
            new Dictionary<string, string>
            {
                ["publicKeyHex"] = "https://w3id.org/security#publicKeyHex"
            }));
        return ctx;
    }

    // ── Multibase helpers ─────────────────────────────────────────────────────

    /// <summary>
    /// Prepends the varint multicodec prefix for <paramref name="keyType"/> then
    /// base58btc-encodes the result (multibase 'z' prefix).
    /// Uses <see cref="KeyTypeExtensions.GetMulticodec"/> so the prefix is always
    /// in sync with the rest of the codebase — no hand-rolled magic numbers.
    /// </summary>
    private static string EncodeMultibase(byte[] keyBytes, KeyType keyType)
    {
        var code        = keyType.GetMulticodec();          // e.g. 0xed for Ed25519
        var prefixBytes = EncodeVarint(code);
        var combined    = new byte[prefixBytes.Length + keyBytes.Length];
        prefixBytes.CopyTo(combined, 0);
        keyBytes.CopyTo(combined, prefixBytes.Length);
        return Multibase.Encode(combined, MultibaseEncoding.Base58Btc);
    }

    /// <summary>Encodes raw bytes (already containing multicodec prefix) as base58btc multibase.</summary>
    private static string EncodeMultibaseRaw(byte[] bytes)
        => Multibase.Encode(bytes, MultibaseEncoding.Base58Btc);

    private static byte[] EncodeVarint(ulong value)
    {
        var result = new List<byte>();
        while (value > 0x7F)
        {
            result.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        result.Add((byte)value);
        return [.. result];
    }

    // ── Private entry types ───────────────────────────────────────────────────

    private record DelegateEntry(string DelegateType, string DelegateAddress, ulong ValidTo);
    private record AttributeEntry(string Name, byte[] Value, ulong ValidTo);
    private record ServiceEntry(string ServiceName, string Endpoint, ulong ValidTo);

    /// <summary>Converts a 0x-prefixed lowercase hex address to EIP-55 checksummed form.</summary>
    private static string Checksum(string hexAddress)
    {
        var hex = hexAddress.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? hexAddress[2..] : hexAddress;
        return ToChecksumAddress(Convert.FromHexString(hex));
    }
}
