using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

public class DecodeAuthorizationCallbackStatePlugin()
    : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;
    private readonly JsonWebTokenHandler _jwtHandler = new();

    internal static class InputParameterNames
    {
        internal const string State = nameof(State);
    }

    internal static class OutputParameterNames
    {
        internal const string OneTimeRedirectUrl = nameof(OneTimeRedirectUrl);
    }

    protected override void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        )
    {
        info ??= new(serviceProvider);
        AzurePluginUtility azureUtility = new(serviceProvider);

        var context = serviceProvider.Get<IPluginExecutionContext>();
        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;

        if (!inputs.TryGetValue(
            InputParameterNames.State,
            out string stateJwtEncodedText) ||
            string.IsNullOrEmpty(stateJwtEncodedText))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.State}"
                );
        }

        JsonWebToken stateJwt;
        try
        {
            stateJwt = _jwtHandler.ReadJsonWebToken(stateJwtEncodedText);
        }
        catch (Exception jwtjweReadExcept)
        {
            info.TracingService.Trace(
                "While reading state parameter as JWT: {0}",
                jwtjweReadExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to read provided parameter '{InputParameterNames.State}' as a JWT in compact serialization format: {jwtjweReadExcept.Message}"
                );
        }
        if (!stateJwt.IsEncrypted)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Specified parameter '{InputParameterNames.State}' is not an encrpted JSON Web Token."
                );
        }

        SecurityKey stateJweSecurityKey;
        if (JwtConstants.DirectKeyUseAlg.Equals(stateJwt.Alg, OrdInv))
        {
            if (string.IsNullOrEmpty(stateJwt.Kid))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing Key Vault claims in JWE header in parameter '{InputParameterNames.State}'. JWE header value '{JwtHeaderParameterNames.Kid}' was expected to refer to the ID of a Key Vault Secret."
                    );
            }

            if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(stateJwt.Enc, OrdInv))
            {
                Uri keyVaultSecretUri = new(stateJwt.Kid, UriKind.Absolute);
                if (!KeyVaultSecretIdentifier.TryCreate(keyVaultSecretUri, out var keyVaultSecretId))
                {
                    info.TracingService.Trace(
                        "Unable to create Key Vault Secret ID from URI: {0}",
                        keyVaultSecretUri
                        );
                    throw new InvalidPluginExecutionException(
                        httpStatus: PluginHttpStatusCode.BadRequest,
                        message: $"Specified JWE specifies an invalid URI for a Key Vault Secret. URI: {keyVaultSecretUri}"
                        );
                }
                SecretClient keyVaultClient = new(
                    keyVaultSecretId.VaultUri,
                    azureUtility.PluginAzureTokenCredential
                    );
                KeyVaultSecret keyVaultSecretData = keyVaultClient
                    .GetSecretAsync(keyVaultSecretId.Name, keyVaultSecretId.Version)
                    .GetAwaiter().GetResult();
                stateJweSecurityKey = KeyVaultPluginUtility
                    .GetKeyVaultSecretSecurityKey(
                        keyVaultSecretData,
                        keySizeBits: 256
                        );
            }
            else
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Invalid content encryption algorithm in JWE header in parameter '{InputParameterNames.State}': {stateJwt.Enc}"
                    );
            }
        }
        else if (SecurityAlgorithms.RsaOAEP.Equals(stateJwt.Alg, OrdInv))
        {
            string keyVaultRsaKeyId = stateJwt.Kid;
            TokenCredential keyVaultTokenCreds = azureUtility.PluginAzureTokenCredential;
            CryptographyClientOptions keyVaultCryptoClientOptions = new();
            KeyResolver keyVaultKeyResolver = new(keyVaultTokenCreds, keyVaultCryptoClientOptions);
            CryptographyClient keyVaultCryptoClient = keyVaultKeyResolver
                .Resolve(new(keyVaultRsaKeyId, UriKind.Absolute));
            RSAKeyVault keyVaultRsaKey = keyVaultCryptoClient.CreateRSA();
            stateJweSecurityKey = new RsaSecurityKey(keyVaultRsaKey)
            { KeyId = keyVaultRsaKey.KeyId };
        }
        else
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid token encryption algorithm in JWE header in parameter '{InputParameterNames.State}': {stateJwt.Alg}"
                );
        }

        try
        {
            stateJwtEncodedText = _jwtHandler.DecryptToken(stateJwt, new()
            {
                TokenDecryptionKey = stateJweSecurityKey,
            });
        }
        catch (Exception jweDecryptExcept)
        {
            info.TracingService.Trace(
                "While decrypting JWE: {0}",
                jweDecryptExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to decrypt JWE specified in parameter '{InputParameterNames.State}': {jweDecryptExcept.Message}"
                );
        }
        try
        {
            stateJwt = _jwtHandler.ReadJsonWebToken(stateJwtEncodedText);
        }
        catch (Exception jwtReadExcept)
        {
            info.TracingService.Trace(
                "While reading decrypted JWT: {0}",
                jwtReadExcept
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to read decrypted payload as JWT specified in parameter '{InputParameterNames.State}': {jwtReadExcept.Message}"
                );
        }
#pragma warning disable CA5404 // Do not disable token validation checks
        TokenValidationResult stateJwtValidateResult = _jwtHandler.ValidateTokenAsync(stateJwt, new()
        {
            ValidateLifetime = true,
            ValidTypes = [JwtConstants.TokenType],
            RequireSignedTokens = false,
            ValidateAudience = false,
            ValidateIssuer = false,
        }).GetAwaiter().GetResult();
#pragma warning restore CA5404 // Do not disable token validation checks
        if (!stateJwtValidateResult.IsValid)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid embedded JWT specified in parameter '{InputParameterNames.State}': {stateJwtValidateResult.Exception?.Message}"
                );
        }
        if (!stateJwt.TryGetValue(
            GetAuthorizationUrlPlugin.JwtClaimNames.OneTimeRedirectUri,
            out string oneTimeRedirectUri) ||
            string.IsNullOrEmpty(oneTimeRedirectUri)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Embedded JWT specified in parameter '{InputParameterNames.State}' is missing required claim: {GetAuthorizationUrlPlugin.JwtClaimNames.OneTimeRedirectUri}"
                );
        }

        outputs[OutputParameterNames.OneTimeRedirectUrl] = oneTimeRedirectUri;
    }
}