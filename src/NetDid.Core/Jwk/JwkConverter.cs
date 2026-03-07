using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Crypto;
using NetDid.Core.Encoding;

namespace NetDid.Core.Jwk;

/// <summary>
/// Converts between <see cref="KeyPair"/> and JSON Web Key (JWK) representations.
/// </summary>
public static class JwkConverter
{
    /// <summary>Convert a KeyPair to a public-only JWK.</summary>
    public static JsonWebKey ToPublicJwk(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        return keyPair.KeyType switch
        {
            KeyType.Ed25519 => CreateOkpJwk("Ed25519", keyPair.PublicKey),
            KeyType.X25519 => CreateOkpJwk("X25519", keyPair.PublicKey),
            KeyType.P256 => CreateEcJwk("P-256", keyPair.PublicKey),
            KeyType.P384 => CreateEcJwk("P-384", keyPair.PublicKey),
            KeyType.Secp256k1 => CreateEcJwk("secp256k1", keyPair.PublicKey),
            KeyType.Bls12381G1 => CreateOkpJwk("BLS12381G1", keyPair.PublicKey),
            KeyType.Bls12381G2 => CreateOkpJwk("BLS12381G2", keyPair.PublicKey),
            _ => throw new ArgumentException($"Unsupported key type: {keyPair.KeyType}")
        };
    }

    /// <summary>Convert a KeyPair to a JWK that includes private key material.</summary>
    public static JsonWebKey ToPrivateJwk(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        var jwk = ToPublicJwk(keyPair);
        jwk.D = Base64UrlNoPadding.Encode(keyPair.PrivateKey);
        return jwk;
    }

    /// <summary>
    /// Extract the key type and raw public key bytes from a JWK.
    /// Inverse of ToPublicJwk.
    /// </summary>
    public static (KeyType KeyType, byte[] PublicKey) ExtractPublicKey(JsonWebKey jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        if (jwk.Kty == "OKP")
        {
            var keyType = jwk.Crv switch
            {
                "Ed25519" => KeyType.Ed25519,
                "X25519" => KeyType.X25519,
                "BLS12381G1" => KeyType.Bls12381G1,
                "BLS12381G2" => KeyType.Bls12381G2,
                _ => throw new ArgumentException($"Unsupported OKP curve: {jwk.Crv}")
            };
            var publicKey = Base64UrlNoPadding.Decode(jwk.X);
            return (keyType, publicKey);
        }

        if (jwk.Kty == "EC")
        {
            var keyType = jwk.Crv switch
            {
                "P-256" => KeyType.P256,
                "P-384" => KeyType.P384,
                "secp256k1" => KeyType.Secp256k1,
                _ => throw new ArgumentException($"Unsupported EC curve: {jwk.Crv}")
            };
            var x = Base64UrlNoPadding.Decode(jwk.X);
            var y = Base64UrlNoPadding.Decode(jwk.Y);
            // Reconstruct uncompressed public key: 0x04 || x || y
            var publicKey = new byte[1 + x.Length + y.Length];
            publicKey[0] = 0x04;
            x.CopyTo(publicKey, 1);
            y.CopyTo(publicKey, 1 + x.Length);
            return (keyType, publicKey);
        }

        throw new ArgumentException($"Unsupported JWK key type: {jwk.Kty}");
    }

    private static JsonWebKey CreateOkpJwk(string crv, byte[] publicKey)
    {
        return new JsonWebKey
        {
            Kty = "OKP",
            Crv = crv,
            X = Base64UrlNoPadding.Encode(publicKey)
        };
    }

    private static JsonWebKey CreateEcJwk(string crv, byte[] publicKey)
    {
        // Public key should be in uncompressed format: 0x04 || x || y
        // or raw x || y (without the 0x04 prefix)
        byte[] x, y;

        if (publicKey.Length > 0 && publicKey[0] == 0x04)
        {
            var coordLen = (publicKey.Length - 1) / 2;
            x = publicKey[1..(1 + coordLen)];
            y = publicKey[(1 + coordLen)..];
        }
        else
        {
            // Assume raw x || y
            var coordLen = publicKey.Length / 2;
            x = publicKey[..coordLen];
            y = publicKey[coordLen..];
        }

        return new JsonWebKey
        {
            Kty = "EC",
            Crv = crv,
            X = Base64UrlNoPadding.Encode(x),
            Y = Base64UrlNoPadding.Encode(y)
        };
    }
}
