using System.Text;
using DataProofsDotnet;
using NetCrypto;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>Validates did:webvh 1.0 witness parameter shape and identities.</summary>
internal static class WitnessPolicyValidator
{
    public static string? GetValidationError(WitnessConfig? config)
    {
        if (config is null || config.IsDisabled)
            return null;

        if (config.ThresholdPropertyPresent.HasValue
            && (config.ThresholdPropertyPresent != true
                || config.WitnessesPropertyPresent != true))
        {
            return "A witness policy must be either an empty object or contain both threshold and witnesses.";
        }

        if (config.Threshold < 1)
            return "Witness threshold must be at least 1 when witnessing is configured.";

        if (config.Witnesses is not { Count: > 0 })
            return "A configured witness policy must contain at least one witness.";

        var distinctIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var witness in config.Witnesses)
        {
            if (witness is null || string.IsNullOrWhiteSpace(witness.Id))
                return "Every witness must have a non-empty did:key id.";

            var normalizedId = witness.Id.Normalize(NormalizationForm.FormC);
            if (!string.Equals(witness.Id, normalizedId, StringComparison.Ordinal))
                return $"Witness id '{witness.Id}' must use its NFC-normalized form.";

            if (!distinctIds.Add(normalizedId))
                return $"Witness id '{witness.Id}' is duplicated.";

            var multibase = WebVhProofVerifier.ExtractDidKeyMultibase(normalizedId);
            if (multibase is null
                || !string.Equals(normalizedId, $"did:key:{multibase}", StringComparison.Ordinal))
            {
                return $"Witness id '{witness.Id}' must be a bare did:key DID.";
            }

            try
            {
                if (PublicKeyMaterial.FromMultikey(multibase).KeyType != KeyType.Ed25519)
                    return $"Witness id '{witness.Id}' must contain an Ed25519 key.";
            }
            catch
            {
                return $"Witness id '{witness.Id}' does not contain valid public key material.";
            }
        }

        if (config.Threshold > distinctIds.Count)
        {
            return $"Witness threshold {config.Threshold} exceeds the number of distinct witnesses " +
                $"({distinctIds.Count}).";
        }

        return null;
    }
}
