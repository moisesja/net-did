using System.Numerics;
using System.Security.Cryptography;

namespace NetDid.Core.Crypto;

/// <summary>
/// Validates that an EC public key represents a point on the stated curve. This is the
/// defense against the invalid-curve attack (Antipa et al., PKC 2003; Jager–Schwenk–Somorovsky,
/// ESORICS 2015 — JOSE/JWE variant) whereby a malicious peer sends off-curve `(x, y)` coordinates
/// during ECDH and recovers the victim's static private key bit-by-bit.
/// </summary>
/// <remarks>
/// RFC 7518 §6.2.2 requires implementations to validate `epk` against the stated curve before
/// key agreement. Curve25519/Ed25519 do not need this — all encoded points are on-curve — so
/// this validator only applies to NIST curves (P-256, P-384, P-521) and secp256k1.
/// </remarks>
public static class EcPointValidator
{
    /// <summary>
    /// Throws <see cref="CryptographicException"/> if <paramref name="x"/> and <paramref name="y"/>
    /// do not represent a valid public-key point on the curve for <paramref name="keyType"/>.
    /// </summary>
    /// <param name="keyType">An EC key type (P-256, P-384, P-521, or secp256k1). Non-EC types are a no-op.</param>
    /// <param name="x">Big-endian X coordinate. Zero-pads accepted.</param>
    /// <param name="y">Big-endian Y coordinate. Zero-pads accepted.</param>
    /// <exception cref="CryptographicException">If any coordinate is out of range, both are zero
    /// (point at infinity), or the point does not satisfy the curve equation.</exception>
    public static void EnsureOnCurve(KeyType keyType, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        if (!TryGetCurveParams(keyType, out var p, out var a, out var b))
            return; // Non-EC type or curve without explicit params; nothing to check here.

        var xi = new BigInteger(x, isUnsigned: true, isBigEndian: true);
        var yi = new BigInteger(y, isUnsigned: true, isBigEndian: true);

        if (xi >= p || yi >= p)
            throw new CryptographicException("EC public key coordinate is out of range for the stated curve.");

        if (xi.IsZero && yi.IsZero)
            throw new CryptographicException("EC public key is the identity (point at infinity).");

        // y² ≡ x³ + a·x + b (mod p)
        var lhs = BigInteger.ModPow(yi, 2, p);
        var rhs = (BigInteger.ModPow(xi, 3, p) + a * xi % p + b) % p;
        if (rhs < 0) rhs += p;

        if (lhs != rhs)
            throw new CryptographicException("EC public key is not on the stated curve.");
    }

    private static bool TryGetCurveParams(KeyType keyType, out BigInteger p, out BigInteger a, out BigInteger b)
    {
        switch (keyType)
        {
            case KeyType.P256:
                (p, b) = DefaultCryptoProvider.GetCurveParams(ECCurve.NamedCurves.nistP256);
                a = p - 3;
                return true;
            case KeyType.P384:
                (p, b) = DefaultCryptoProvider.GetCurveParams(ECCurve.NamedCurves.nistP384);
                a = p - 3;
                return true;
            case KeyType.P521:
                (p, b) = DefaultCryptoProvider.GetCurveParams(ECCurve.NamedCurves.nistP521);
                a = p - 3;
                return true;
            case KeyType.Secp256k1:
                // secp256k1: p = 2^256 − 2^32 − 977, a = 0, b = 7. Not in GetCurveParams (which
                // is keyed by ECCurve OID for NIST curves); inline the constants here.
                p = BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
                    System.Globalization.NumberStyles.HexNumber);
                a = BigInteger.Zero;
                b = 7;
                return true;
            default:
                p = default;
                a = default;
                b = default;
                return false;
        }
    }
}
