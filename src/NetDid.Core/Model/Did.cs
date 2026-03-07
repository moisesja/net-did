using NetDid.Core.Exceptions;
using NetDid.Core.Parsing;

namespace NetDid.Core.Model;

/// <summary>
/// A validated W3C DID. If a <see cref="Did"/> exists, it is guaranteed syntactically valid.
/// </summary>
public readonly record struct Did
{
    public string Value { get; }
    public string Method { get; }
    public string MethodSpecificId { get; }

    public Did(string value)
    {
        if (!DidParser.IsValid(value))
            throw new InvalidDidException(value, $"'{value}' does not conform to W3C DID syntax.");

        Value = value;
        Method = DidParser.ExtractMethod(value)!;
        MethodSpecificId = DidParser.ExtractMethodSpecificId(value)!;
    }

    /// <summary>Implicit conversion from string — validates on construction.</summary>
    public static implicit operator Did(string value) => new(value);

    /// <summary>Implicit conversion to string for interop.</summary>
    public static implicit operator string(Did did) => did.Value;

    public override string ToString() => Value;
}
