using System.Text.Json;
using System.Text.Json.Serialization;
using NetDid.Core.Crypto;

namespace NetDid.Tools.WebVhCli.State;

internal sealed class StoredKey
{
    [JsonPropertyName("keyType")]
    public string KeyType { get; set; } = "Ed25519";

    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; } = "";

    [JsonPropertyName("privateKey")]
    public string PrivateKey { get; set; } = "";

    [JsonPropertyName("multibasePublicKey")]
    public string MultibasePublicKey { get; set; } = "";
}

internal sealed class KeyStoreData
{
    [JsonPropertyName("keys")]
    public Dictionary<string, StoredKey> Keys { get; set; } = new();
}

internal static class KeyStore
{
    private const string FileName = "key-store.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static string GetPath(string outputDir) => Path.Combine(outputDir, FileName);

    public static KeyStoreData Load(string outputDir)
    {
        var path = GetPath(outputDir);
        if (!File.Exists(path))
            return new KeyStoreData();

        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<KeyStoreData>(json, JsonOptions) ?? new KeyStoreData();
    }

    public static void Save(string outputDir, KeyStoreData store)
    {
        Directory.CreateDirectory(outputDir);
        var json = JsonSerializer.Serialize(store, JsonOptions);
        File.WriteAllText(GetPath(outputDir), json);
    }

    public static void AddKey(string outputDir, string name, KeyPair keyPair)
    {
        var store = Load(outputDir);
        store.Keys[name] = new StoredKey
        {
            KeyType = keyPair.KeyType.ToString(),
            PublicKey = Convert.ToBase64String(keyPair.PublicKey),
            PrivateKey = Convert.ToBase64String(keyPair.PrivateKey),
            MultibasePublicKey = keyPair.MultibasePublicKey
        };
        Save(outputDir, store);
    }

    public static KeyPair? GetKeyPair(string outputDir, string name)
    {
        var store = Load(outputDir);
        if (!store.Keys.TryGetValue(name, out var stored))
            return null;

        var keyGen = new DefaultKeyGenerator();
        var keyType = Enum.Parse<KeyType>(stored.KeyType);
        var privateKey = Convert.FromBase64String(stored.PrivateKey);
        return keyGen.FromPrivateKey(keyType, privateKey);
    }
}
