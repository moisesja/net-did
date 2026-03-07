namespace NetDid.Core.Encoding;

public enum MultibaseEncoding
{
    /// <summary>Base58 Bitcoin encoding, prefix 'z'.</summary>
    Base58Btc,

    /// <summary>Base64 URL-safe no-padding encoding, prefix 'u'.</summary>
    Base64Url,

    /// <summary>Base32 lowercase encoding, prefix 'b'.</summary>
    Base32Lower
}
