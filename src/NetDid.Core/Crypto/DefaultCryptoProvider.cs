using System.Security.Cryptography;
using NBitcoin.Secp256k1;
using NSec.Cryptography;
using SHA256 = System.Security.Cryptography.SHA256;

namespace NetDid.Core.Crypto;

/// <summary>
/// Default implementation of <see cref="ICryptoProvider"/> supporting Ed25519, X25519,
/// P-256, P-384, secp256k1, and BLS12-381 G1/G2.
/// </summary>
public sealed class DefaultCryptoProvider : ICryptoProvider
{
    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        return keyType switch
        {
            KeyType.Ed25519 => SignEd25519(privateKey, data),
            KeyType.P256 => SignEcDsa(privateKey, data, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
            KeyType.P384 => SignEcDsa(privateKey, data, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
            KeyType.Secp256k1 => SignSecp256k1(privateKey, data),
            KeyType.X25519 => throw new ArgumentException("X25519 is a key agreement algorithm, not a signing algorithm."),
            KeyType.Bls12381G1 or KeyType.Bls12381G2 => SignBls(keyType, privateKey, data),
            _ => throw new ArgumentException($"Unsupported key type for signing: {keyType}")
        };
    }

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        return keyType switch
        {
            KeyType.Ed25519 => VerifyEd25519(publicKey, data, signature),
            KeyType.P256 => VerifyEcDsa(publicKey, data, signature, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256),
            KeyType.P384 => VerifyEcDsa(publicKey, data, signature, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384),
            KeyType.Secp256k1 => VerifySecp256k1(publicKey, data, signature),
            KeyType.X25519 => throw new ArgumentException("X25519 is a key agreement algorithm, not a verification algorithm."),
            KeyType.Bls12381G1 or KeyType.Bls12381G2 => VerifyBls(keyType, publicKey, data, signature),
            _ => throw new ArgumentException($"Unsupported key type for verification: {keyType}")
        };
    }

    public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var algorithm = NSec.Cryptography.KeyAgreementAlgorithm.X25519;

        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey);
        var pubKey = NSec.Cryptography.PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);

        using var sharedSecret = algorithm.Agree(key, pubKey)
            ?? throw new CryptographicException("X25519 key agreement failed.");

        // Extract the raw shared secret - use a key derivation to get usable bytes
        var kdf = KeyDerivationAlgorithm.HkdfSha256;
        using var derivedKey = kdf.DeriveKey(sharedSecret, ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty, AeadAlgorithm.ChaCha20Poly1305,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return derivedKey.Export(KeyBlobFormat.RawSymmetricKey);
    }

    // --- Ed25519 (NSec.Cryptography) ---

    private static byte[] SignEd25519(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        var algorithm = SignatureAlgorithm.Ed25519;

        // Our private key is 32-byte seed. NSec's RawPrivateKey expects the seed.
        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return algorithm.Sign(key, data);
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var pubKey = NSec.Cryptography.PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);
        return algorithm.Verify(pubKey, data, signature);
    }

    // --- P-256 / P-384 (System.Security.Cryptography.ECDsa) ---

    private static byte[] SignEcDsa(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data,
        ECCurve curve, HashAlgorithmName hashAlgorithm)
    {
        using var ecdsa = ECDsa.Create();
        var parameters = ImportEcPrivateKey(privateKey, curve);
        ecdsa.ImportParameters(parameters);
        return ecdsa.SignData(data.ToArray(), hashAlgorithm);
    }

    private static bool VerifyEcDsa(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature, ECCurve curve, HashAlgorithmName hashAlgorithm)
    {
        using var ecdsa = ECDsa.Create();
        var parameters = ImportEcPublicKey(publicKey, curve);
        ecdsa.ImportParameters(parameters);
        return ecdsa.VerifyData(data.ToArray(), signature.ToArray(), hashAlgorithm);
    }

    internal static ECParameters ImportEcPrivateKey(ReadOnlySpan<byte> privateKey, ECCurve curve)
    {
        return new ECParameters
        {
            Curve = curve,
            D = privateKey.ToArray()
        };
    }

    internal static ECParameters ImportEcPublicKey(ReadOnlySpan<byte> publicKey, ECCurve curve)
    {
        // Handle both uncompressed (0x04 || x || y) and raw (x || y)
        int offset = 0;
        int coordLen;

        if (publicKey.Length > 0 && publicKey[0] == 0x04)
        {
            offset = 1;
            coordLen = (publicKey.Length - 1) / 2;
        }
        else
        {
            coordLen = publicKey.Length / 2;
        }

        return new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = publicKey.Slice(offset, coordLen).ToArray(),
                Y = publicKey.Slice(offset + coordLen, coordLen).ToArray()
            }
        };
    }

    // --- secp256k1 (NBitcoin.Secp256k1) ---

    private static byte[] SignSecp256k1(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        var privKey = ECPrivKey.Create(privateKey);

        // secp256k1 ECDSA expects a 32-byte message hash
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);

        var sig = privKey.SignECDSARFC6979(hash);

        Span<byte> compact = stackalloc byte[64];
        sig.WriteCompactToSpan(compact);
        return compact.ToArray();
    }

    private static bool VerifySecp256k1(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (!ECPubKey.TryCreate(publicKey, null, out _, out var pubKey))
            return false;

        if (!SecpECDSASignature.TryCreateFromCompact(signature, out var sig))
            return false;

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);

        return pubKey.SigVerify(sig, hash);
    }

    // --- BLS12-381 (Nethermind.Crypto.Bls) ---

    private static byte[] SignBls(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        // TODO: Implement BLS12-381 signing using Nethermind.Crypto.Bls
        throw new NotImplementedException($"BLS12-381 {keyType} signing is not yet implemented.");
    }

    private static bool VerifyBls(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        // TODO: Implement BLS12-381 verification using Nethermind.Crypto.Bls
        throw new NotImplementedException($"BLS12-381 {keyType} verification is not yet implemented.");
    }
}
