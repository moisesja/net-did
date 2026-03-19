# Serving did:webvh Documents

A `did:webvh` DID resolves to a JSON Lines log file (`did.jsonl`) hosted at an HTTPS URL. This guide covers how to configure a web server to serve the required files.

## File Layout

When you create a `did:webvh` DID using NetDid, the `CreateAsync` result includes two artifacts:

| Artifact | Description |
|----------|-------------|
| `did.jsonl` | The DID log (JSON Lines format). Required for resolution. |
| `did.json` | A `did:web`-compatible DID Document. Optional, enables `did:web` compatibility. |

### Root-level DID

For `did:webvh:SCID:example.com`:

```
https://example.com/.well-known/did.jsonl
https://example.com/.well-known/did.json    (optional)
```

### Path-based DID

For `did:webvh:SCID:example.com:users:alice`:

```
https://example.com/users/alice/did.jsonl
https://example.com/users/alice/did.json    (optional)
```

## Quick Start with ASP.NET Core

```csharp
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Serve did.jsonl from .well-known for root DIDs
app.MapGet("/.well-known/did.jsonl", async () =>
{
    var content = await File.ReadAllBytesAsync("data/did.jsonl");
    return Results.Bytes(content, "application/jsonl+json");
});

// Serve did.json for did:web compatibility
app.MapGet("/.well-known/did.json", async () =>
{
    var content = await File.ReadAllBytesAsync("data/did.json");
    return Results.Bytes(content, "application/did+ld+json");
});

// Path-based DIDs
app.MapGet("/{**path}/did.jsonl", async (string path) =>
{
    var filePath = Path.Combine("data", path, "did.jsonl");
    if (!File.Exists(filePath)) return Results.NotFound();
    var content = await File.ReadAllBytesAsync(filePath);
    return Results.Bytes(content, "application/jsonl+json");
});

app.Run();
```

## NGINX

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # Root DID: did:webvh:SCID:example.com
    location /.well-known/did.jsonl {
        root /var/www/did;
        default_type application/jsonl+json;
        add_header Access-Control-Allow-Origin "*";
        add_header Cache-Control "public, max-age=300";
    }

    location /.well-known/did.json {
        root /var/www/did;
        default_type application/did+ld+json;
        add_header Access-Control-Allow-Origin "*";
    }

    # Path-based DIDs: did:webvh:SCID:example.com:users:alice
    location ~ ^/(.+)/did\.jsonl$ {
        root /var/www/did;
        default_type application/jsonl+json;
        add_header Access-Control-Allow-Origin "*";
        add_header Cache-Control "public, max-age=300";
    }
}
```

File layout:
```
/var/www/did/.well-known/did.jsonl
/var/www/did/.well-known/did.json
/var/www/did/users/alice/did.jsonl
```

## Apache

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/did

    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key

    <Directory /var/www/did>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>

    # MIME types
    AddType application/jsonl+json .jsonl
    AddType application/did+ld+json .json

    # CORS
    Header set Access-Control-Allow-Origin "*"
    Header set Cache-Control "public, max-age=300"
</VirtualHost>
```

## Caddy

```caddyfile
example.com {
    # Root DID
    handle /.well-known/did.jsonl {
        root * /var/www/did
        file_server
        header Content-Type "application/jsonl+json"
        header Access-Control-Allow-Origin "*"
    }

    handle /.well-known/did.json {
        root * /var/www/did
        file_server
        header Content-Type "application/did+ld+json"
        header Access-Control-Allow-Origin "*"
    }

    # Path-based DIDs
    handle_path /*/did.jsonl {
        root * /var/www/did
        file_server
        header Content-Type "application/jsonl+json"
        header Access-Control-Allow-Origin "*"
    }
}
```

## Cloud Static Hosting

### Azure Blob Storage

1. Create a storage account with static website hosting enabled
2. Upload `did.jsonl` to `$web/.well-known/did.jsonl`
3. Configure custom domain with HTTPS (Azure CDN or Front Door)
4. Set blob content type to `application/jsonl+json`

```bash
az storage blob upload \
  --account-name myaccount \
  --container-name '$web' \
  --name '.well-known/did.jsonl' \
  --file did.jsonl \
  --content-type 'application/jsonl+json'
```

### AWS S3 + CloudFront

1. Create an S3 bucket with static website hosting
2. Upload files with correct content types
3. Create a CloudFront distribution with HTTPS

```bash
aws s3 cp did.jsonl s3://my-bucket/.well-known/did.jsonl \
  --content-type 'application/jsonl+json'
```

### Google Cloud Storage

```bash
gsutil cp -h "Content-Type:application/jsonl+json" \
  did.jsonl gs://my-bucket/.well-known/did.jsonl
```

## Requirements

### HTTPS (Required)

All `did:webvh` URLs MUST use HTTPS. The spec does not allow plain HTTP. Ensure your server has a valid TLS certificate.

### CORS Headers (Recommended)

For browser-based resolution, include CORS headers:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

### Content Types

| File | Content-Type |
|------|-------------|
| `did.jsonl` | `application/jsonl+json` |
| `did.json` | `application/did+ld+json` |

### Caching

The log file grows over time as updates are appended. Use short cache durations (5-15 minutes) to balance performance with freshness:

```
Cache-Control: public, max-age=300
```

## Updating the DID

When you call `UpdateAsync` or `DeactivateAsync`, NetDid returns updated artifacts. Replace the served files with the new content:

```csharp
var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
{
    CurrentLogContent = File.ReadAllBytes("data/did.jsonl"),
    SigningKey = signer,
    NewDocument = updatedDocument
});

// Write updated artifacts to the web server's file system
File.WriteAllText("data/did.jsonl", (string)updateResult.Artifacts!["did.jsonl"]);
File.WriteAllText("data/did.json", (string)updateResult.Artifacts["did.json"]);
```

## Witness File (Optional)

If your DID uses witnesses, you also need to serve a `did-witness.json` file:

- Root DID: `https://example.com/.well-known/did-witness.json`
- Path DID: `https://example.com/users/alice/did-witness.json`

Content-Type: `application/json`
