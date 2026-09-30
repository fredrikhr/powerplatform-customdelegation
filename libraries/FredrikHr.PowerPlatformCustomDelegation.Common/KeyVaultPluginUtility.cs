using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public static class KeyVaultPluginUtility
{
    public const string KeyIdUseKeyVaultId = "<use-keyvault-id>";
    private static readonly UTF8Encoding Utf8Encoding =
        new(encoderShouldEmitUTF8Identifier: false);

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Security",
        "CA5379: Ensure Key Derivation Function algorithm is sufficiently strong",
        Justification = ".NET Framework"
        )]
    public static SymmetricSecurityKey GetKeyVaultSecretSecurityKey(
        KeyVaultSecret keyVaultSecret,
        int keySizeBits
        )
    {
        _ = keyVaultSecret ?? throw new ArgumentNullException(nameof(keyVaultSecret));
        string keyVaultSecretId = keyVaultSecret.Id.ToString();
        byte[] keyDerivationSalt = Utf8Encoding.GetBytes(keyVaultSecretId);
        const int bitsPerByte = 8;
        using Rfc2898DeriveBytes keyDerivationAlg = new(
            password: keyVaultSecret.Value,
            salt: keyDerivationSalt,
            iterations: 100_000
            );
        byte[] keyBytes = keyDerivationAlg.GetBytes(keySizeBits / bitsPerByte);
        SymmetricSecurityKey jweKey = new(keyBytes) { KeyId = keyVaultSecretId };
        return jweKey;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability",
        "CA2000: Dispose objects before losing scope",
        Justification = nameof(X509SecurityKey)
        )]
    public static X509SecurityKey GetKeyVaultPublicX509SecurityKey(
        KeyVaultCertificate keyVaultCertificate
        )
    {
        _ = keyVaultCertificate ?? throw new ArgumentNullException(nameof(keyVaultCertificate));
        X509Certificate2 x509Certificate = new(keyVaultCertificate.Cer);
        return new(x509Certificate, keyVaultCertificate.Id.ToString());
    }

    public static async Task<(KeyVaultCertificate certInfo, RsaSecurityKey rsaKey)> GetKeyVaultPrivateRsaSecurityKeyAsync(
        TokenCredential tokenCredential,
        KeyVaultCertificateIdentifier keyVaultCertificateId,
        string? keyId = null
        )
    {
        KeyVaultCertificate keyVaultCertificateInfo = await GetKeyVaultCertificateAsync(
            tokenCredential,
            keyVaultCertificateId
            ).ConfigureAwait(continueOnCapturedContext: false);
        RsaSecurityKey keyVaultRsaKey = await GetKeyVaultPrivateRsaSecurityKeyAsync(
            tokenCredential, keyVaultCertificateInfo, keyId
            ).ConfigureAwait(continueOnCapturedContext: false);
        return (keyVaultCertificateInfo, keyVaultRsaKey);
    }

    public static async Task<(KeyVaultCertificate certInfo, RsaSecurityKey rsaKey)> GetKeyVaultPrivateRsaSecurityKeyAsync(
        TokenCredential tokenCredential,
        Uri keyVaultCertificateUri,
        string? keyId = null
        )
    {
        KeyVaultCertificate keyVaultCertificateInfo = await GetKeyVaultCertificateAsync(
            tokenCredential, new(keyVaultCertificateUri)
            ).ConfigureAwait(continueOnCapturedContext: false);
        RsaSecurityKey keyVaultRsaKey = await GetKeyVaultPrivateRsaSecurityKeyAsync(
            tokenCredential, keyVaultCertificateInfo, keyId
            ).ConfigureAwait(continueOnCapturedContext: false);
        return (keyVaultCertificateInfo, keyVaultRsaKey);
    }

    public static async Task<RsaSecurityKey> GetKeyVaultPrivateRsaSecurityKeyAsync(
        TokenCredential tokenCredential,
        KeyVaultCertificate keyVaultCertificateInfo,
        string? keyId = null
        )
    {
        _ = keyVaultCertificateInfo ?? throw new ArgumentNullException(nameof(keyVaultCertificateInfo));
        CryptographyClientOptions keyVaultCryptoClientOptions = new();
        KeyResolver keyVaultKeyResolver = new(tokenCredential, keyVaultCryptoClientOptions);
        CryptographyClient keyVaultCryptoClient = await keyVaultKeyResolver
            .ResolveAsync(keyVaultCertificateInfo.KeyId)
            .ConfigureAwait(continueOnCapturedContext: false);
        RSAKeyVault keyVaultRsaKey = await keyVaultCryptoClient
            .CreateRSAAsync()
            .ConfigureAwait(continueOnCapturedContext: false);
        RsaSecurityKey keyVaultRsaSecKey = new(keyVaultRsaKey);
        if (!string.IsNullOrEmpty(keyId))
        {
            keyVaultRsaSecKey.KeyId =
                KeyIdUseKeyVaultId.Equals(keyId, StringComparison.Ordinal)
                ? keyVaultCertificateInfo.KeyId.ToString()
                : keyId;
        }
        return keyVaultRsaSecKey;
    }

    public static Func<AssertionRequestOptions, Task<string>> GetKeyVaultCertificateAssertionProvider(
        TokenCredential tokenCredential,
        KeyVaultCertificateIdentifier keyVaultCertificateId,
        string? keyId = null,
        string? assertionJwtAlgorithm = null,
        bool sendX5c = false
        )
    {
        Task<(KeyVaultCertificate info, SigningCredentials signCreds, string assertionHeaderEncoded)> keyVaultCertificateStaticTask =
            GetClientAssertionStaticData(
                tokenCredential,
                keyVaultCertificateId,
                keyId,
                assertionJwtAlgorithm,
                sendX5c
            );

        return GetClientAssertion;

        async Task<string> GetClientAssertion(AssertionRequestOptions context)
        {
            var (info, signCreds, assertionHeaderEncoded) = await keyVaultCertificateStaticTask
                .ConfigureAwait(continueOnCapturedContext: false);
            DateTime assertionIssuedAt = DateTime.UtcNow;
            System.IdentityModel.Tokens.Jwt.JwtPayload assertionPayload = new(
                issuer: context.ClientID,
                audience: context.TokenEndpoint,
                notBefore: assertionIssuedAt,
                expires: assertionIssuedAt.AddMinutes(2),
                issuedAt: assertionIssuedAt,
                claims: [
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new(JwtRegisteredClaimNames.Sub, context.ClientID),
                ]);
            string assertionSignInput =
                $"{assertionHeaderEncoded}.{assertionPayload.Base64UrlEncode()}";
            string assertionSignature = JwtTokenUtilities.CreateEncodedSignature(
                assertionSignInput,
                signCreds
                );
            return $"{assertionSignInput}.{assertionSignature}";
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage(
            "Security",
            "CA5350: Do Not Use Weak Cryptographic Algorithms",
            Justification = nameof(X509Certificate2)
            )]
        static async Task<(KeyVaultCertificate info, SigningCredentials signCreds, string assertionHeaderEncoded)>
        GetClientAssertionStaticData(
            TokenCredential tokenCredential,
            KeyVaultCertificateIdentifier keyVaultCertificateId,
            string? kidJwtHeaderClaim = null,
            string? assertionJwtAlgorithm = null,
            bool sendX5c = false
            )
        {
            KeyVaultCertificate keyVaultCertificateInfo = await GetKeyVaultCertificateAsync(
                tokenCredential,
                keyVaultCertificateId
                ).ConfigureAwait(continueOnCapturedContext: false);
            Task<RsaSecurityKey> keyVaultRsaKeyTask = GetKeyVaultPrivateRsaSecurityKeyAsync(
                tokenCredential, keyVaultCertificateInfo, kidJwtHeaderClaim
                );
            using var sha1 = SHA1.Create();
            string keyVaultCertificateThumbprint = Base64UrlEncoder.Encode(
                sha1.ComputeHash(keyVaultCertificateInfo.Cer)
                );
            using var sha256 = SHA256.Create();
            string keyVaultCertificateThumbprintS256 = Base64UrlEncoder.Encode(
                sha256.ComputeHash(keyVaultCertificateInfo.Cer)
                );
            RsaSecurityKey keyVaultRsaKey = await keyVaultRsaKeyTask
                .ConfigureAwait(continueOnCapturedContext: false);
            SigningCredentials keyVaultSignCreds = new(
                keyVaultRsaKey,
                assertionJwtAlgorithm ?? SecurityAlgorithms.RsaSsaPssSha256
                );
            System.IdentityModel.Tokens.Jwt.JwtHeader assertionHeader = new(keyVaultSignCreds)
            {
                { JwtHeaderParameterNames.X5t, keyVaultCertificateThumbprint },
                { $"{JwtHeaderParameterNames.X5t}#S256", keyVaultCertificateThumbprintS256 },
            };
            if (sendX5c)
            {
                assertionHeader[JwtHeaderParameterNames.X5c] = Base64UrlEncoder
                    .Encode(keyVaultCertificateInfo.Cer);
            }
            return (
                keyVaultCertificateInfo,
                keyVaultSignCreds,
                assertionHeader.Base64UrlEncode()
                );
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Security",
        "CA5350: Do Not Use Weak Cryptographic Algorithms",
        Justification = nameof(X509Certificate2)
        )]
    public static Func<AssertionRequestOptions, Task<string>> GetKeyVaultCertificateAssertionProvider(
        KeyVaultCertificate keyVaultCertificateInfo,
        RsaSecurityKey keyVaultRsaKey,
        bool sendX5c = false
        )
    {
        _ = keyVaultCertificateInfo ?? throw new ArgumentNullException(nameof(keyVaultCertificateInfo));
        using var sha1 = SHA1.Create();
        string keyVaultCertificateThumbprint = Base64UrlEncoder.Encode(
            sha1.ComputeHash(keyVaultCertificateInfo.Cer)
            );
        using var sha256 = SHA256.Create();
        string keyVaultCertificateThumbprintS256 = Base64UrlEncoder.Encode(
            sha256.ComputeHash(keyVaultCertificateInfo.Cer)
            );
        SigningCredentials keyVaultSignCreds = new(
            keyVaultRsaKey,
            SecurityAlgorithms.RsaSsaPssSha256
            );
        System.IdentityModel.Tokens.Jwt.JwtHeader assertionHeader = new(keyVaultSignCreds)
        {
            { JwtHeaderParameterNames.X5t, keyVaultCertificateThumbprint },
            { $"{JwtHeaderParameterNames.X5t}#S256", keyVaultCertificateThumbprintS256 },
        };
        if (sendX5c)
        {
            assertionHeader[JwtHeaderParameterNames.X5c] = Base64UrlEncoder
                .Encode(keyVaultCertificateInfo.Cer);
        }
        string assertionHeaderEncoded = assertionHeader.Base64UrlEncode();

        return GetClientAssertion;

        Task<string> GetClientAssertion(AssertionRequestOptions context)
        {
            DateTime assertionIssuedAt = DateTime.UtcNow;
            System.IdentityModel.Tokens.Jwt.JwtPayload assertionPayload = new(
                issuer: context.ClientID,
                audience: context.TokenEndpoint,
                notBefore: assertionIssuedAt,
                expires: assertionIssuedAt.AddMinutes(2),
                issuedAt: assertionIssuedAt,
                claims: [
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new(JwtRegisteredClaimNames.Sub, context.ClientID),
                ]);
            string assertionSignInput = $"{assertionHeaderEncoded}.{assertionPayload.Base64UrlEncode()}";
            string assertionSignature = JwtTokenUtilities.CreateEncodedSignature(
                assertionSignInput,
                keyVaultSignCreds
                );
            return Task.FromResult($"{assertionSignInput}.{assertionSignature}");
        }
    }

    public static async Task<KeyVaultCertificate> GetKeyVaultCertificateAsync(
        TokenCredential tokenCredential,
        KeyVaultCertificateIdentifier keyVaultCertificateId
        )
    {
        CertificateClient keyVaultClient = new(
            keyVaultCertificateId.VaultUri,
            tokenCredential
            );
        return keyVaultCertificateId is { Version: string certVersion }
            ? await keyVaultClient.GetCertificateVersionAsync(
                keyVaultCertificateId.Name,
                certVersion
                ).ConfigureAwait(continueOnCapturedContext: false)
            : await keyVaultClient.GetCertificateAsync(
                keyVaultCertificateId.Name
                ).ConfigureAwait(continueOnCapturedContext: false)
                ;
    }

    public static async Task<KeyVaultSecret> GetKeyVaultSecretAsync(
        TokenCredential tokenCredential,
        KeyVaultSecretIdentifier keyVaultSecretId
        )
    {
        SecretClient keyVaultClient = new(
            keyVaultSecretId.VaultUri,
            tokenCredential
            );
        return await keyVaultClient.GetSecretAsync(
            keyVaultSecretId.Name,
            keyVaultSecretId.Version
            ).ConfigureAwait(continueOnCapturedContext: false);
    }

    public static KeyVaultSecretIdentifier GetKeyVaultSecretIdentifier(
        Uri keyVaultUri,
        string secretName,
        string? version = null)
    {
        Uri secretIdUri = GetKeyVaultObjectIdUri(keyVaultUri, keytype.Secret, secretName, version);
        return new(secretIdUri);
    }

    public static KeyVaultCertificateIdentifier GetKeyVaultCertificateIdentifier(
        Uri keyVaultUri,
        string certificateName,
        string? version = null)
    {
        Uri secretIdUri = GetKeyVaultObjectIdUri(keyVaultUri, keytype.Certificate, certificateName, version);
        return new(secretIdUri);
    }

    private static Uri GetKeyVaultObjectIdUri(
        Uri keyVaultUri,
        keytype keytype,
        string objectName,
        string? version = null)
    {
        string keyVaultCollectionName = keytype switch
        {
            keytype.Certificate or keytype.CertificateWithX5c => "certificates",
            keytype.Secret or _ => "secrets",
        };
        string keyVaultRelativeUrl = $"/{keyVaultCollectionName}/{objectName}";
        if (!string.IsNullOrEmpty(version))
        {
            keyVaultRelativeUrl += $"/{version}";
        }
        return new(keyVaultUri, keyVaultRelativeUrl);
    }
}