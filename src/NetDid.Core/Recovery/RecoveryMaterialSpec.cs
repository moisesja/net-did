namespace NetDid.Core.Recovery;

/// <summary>
/// Describes the envelope shape of recovery material a DID method emits at bootstrap
/// and consumes during a recovery flow. Returned from <see cref="IDidMethod.RecoveryMaterialSpec"/>
/// when <see cref="IDidMethod.SupportsRecovery"/> is <c>true</c>.
/// </summary>
/// <param name="Kind">
/// Stable identifier for the material shape (e.g. <c>"webvh-log-commitment"</c>,
/// <c>"key-seed-restoration"</c>). Consumers branch on this value to pick the right
/// validator and recovery API path. Concrete kinds are defined per method by the
/// recovery API (see issue #44 / ND-E9).
/// </param>
/// <param name="SchemaVersion">
/// Integer version of the payload schema. Bumped when the wire shape of the material
/// changes in a non-backward-compatible way.
/// </param>
/// <param name="Encoding">
/// How the material payload is encoded on the wire (e.g. <c>"application/json"</c>,
/// <c>"base64url"</c>, <c>"multibase-base58btc"</c>).
/// </param>
public sealed record RecoveryMaterialSpec(string Kind, int SchemaVersion, string Encoding);
