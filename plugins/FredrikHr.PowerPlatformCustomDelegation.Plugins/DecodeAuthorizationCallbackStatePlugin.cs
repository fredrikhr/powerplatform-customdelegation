using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformCustomDelegation.Common;
using FredrikHr.PowerPlatformCustomDelegation.Common.JosePbes2;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;

namespace FredrikHr.PowerPlatformCustomDelegation.Plugins;

public class DecodeAuthorizationCallbackStatePlugin() : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;
    private static readonly Pbes2CryptoProviderFactory Pbes2CryptoProviderFactory = new();
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
        PluginExecutionInformation info)
    {
#if DEBUG
        bool prevShowPii = Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII;
#endif
        try
        {
#if DEBUG
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
#endif

            ExecuteCoreImpl(serviceProvider, info);
        }
        finally
        {
#if DEBUG
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = prevShowPii;
#endif
        }
    }

    private void ExecuteCoreImpl(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info)
    {
        info ??= new(serviceProvider);
        PowerPlatformFicTokenCredential azureCreds = new(serviceProvider);
        AzureUtility azureUtility = new(azureCreds);

        var context = serviceProvider.Get<IPluginExecutionContext>();
        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;

        if (!inputs.TryGetValue(
            InputParameterNames.State,
            out string stateJweText) ||
            string.IsNullOrEmpty(stateJweText))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.State}");
        }

        JsonWebToken stateJwt;
        try
        {
            stateJwt = _jwtHandler.ReadJsonWebToken(stateJweText);
        }
        catch (Exception jwtjweReadExcept)
        {
            info.TracingService.Trace(
                "While reading state parameter as JWT: {0}",
                jwtjweReadExcept);
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Unable to read provided parameter '{InputParameterNames.State}' as a JWT in compact serialization format: {jwtjweReadExcept.Message}");
        }
        if (!stateJwt.IsEncrypted)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Specified parameter '{InputParameterNames.State}' is not an encrpted JSON Web Token.");
        }

        SecurityKey stateJweSecurityKey;
        if (Pbes2CryptoProviderFactory.IsSupportedPbes2KeyWrapAlgorithm(stateJwt.Alg, key: null))
        {
            if (string.IsNullOrEmpty(stateJwt.Kid))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing Key Vault claims in JWE header in parameter '{InputParameterNames.State}'. JWE header value '{JwtHeaderParameterNames.Kid}' was expected to refer to the ID of a Key Vault Secret."
                    );
            }

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
                azureCreds
                );
            KeyVaultSecret keyVaultSecretData = keyVaultClient
                .GetSecretAsync(keyVaultSecretId.Name, keyVaultSecretId.Version)
                .GetAwaiter().GetResult();

            if (!stateJwt.TryGetHeaderValue(
                Pbes2Constants.Pbes2SaltInputHeaderParameter,
                out string? p2s) ||
                p2s is null)
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing JWE Header Parameter '{Pbes2Constants.Pbes2SaltInputHeaderParameter}' required for specified algorithm '{stateJwt.Alg}'.");
            }

            if (!stateJwt.TryGetHeaderValue(
                Pbes2Constants.Pbes2IterationCountHeaderParameter,
                out int p2c))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing JWE Header Parameter '{Pbes2Constants.Pbes2IterationCountHeaderParameter}' required for specified algorithm '{stateJwt.Alg}'.");
            }

            byte[] p2sBytes;
            try
            {
                p2sBytes = Base64UrlEncoder.DecodeBytes(p2s);
            }
            catch (Exception p2sDecodeExcept)
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Specified JWE Header Parameter '{Pbes2Constants.Pbes2SaltInputHeaderParameter}' could not be decoded as a Base64URL encoded octet-string: {p2sDecodeExcept}");
            }

            stateJweSecurityKey = new Pbes2SecurityKey(keyVaultSecretData.Value, p2sBytes)
            {
                KeyId = stateJwt.Kid,
                IterationCount = p2c,
                CryptoProviderFactory = Pbes2CryptoProviderFactory,
            };

            p2sBytes.AsSpan().Clear();
        }
        else if (SecurityAlgorithms.RsaOAEP.Equals(stateJwt.Alg, OrdInv))
        {
            if (string.IsNullOrEmpty(stateJwt.Kid))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing Key Vault claims in JWE header in parameter '{InputParameterNames.State}'. JWE header value '{JwtHeaderParameterNames.Kid}' was expected to refer to the ID of a Key Vault Certificate.");
            }

            stateJweSecurityKey = KeyVaultPluginUtility.GetKeyVaultPrivateX509SecurityKeyAsync(
                azureUtility.TokenCredential,
                new Uri(stateJwt.Kid))
                .GetAwaiter().GetResult();
        }
        else
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid CEK encryption algorithm in JWE header '{JwtHeaderParameterNames.Alg}' in parameter '{InputParameterNames.State}': {stateJwt.Alg}");
        }

        string stateDecryptedJwtString;
        try
        {
            stateDecryptedJwtString = _jwtHandler.DecryptToken(stateJwt, new()
            {
                TokenDecryptionKey = stateJweSecurityKey,
            });
        }
        catch (Exception jweDecryptExcept)
        {
            serviceProvider.Get<ITracingService>()?.Trace(
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
            stateJwt = _jwtHandler.ReadJsonWebToken(stateDecryptedJwtString);
        }
        catch (Exception jwtReadExcept)
        {
            serviceProvider.Get<ITracingService>()?.Trace(
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
            info.TracingService.Trace(
                "While decrypting JWE: {0}",
                stateJwtValidateResult.Exception);
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid embedded JWT specified in parameter '{InputParameterNames.State}': {stateJwtValidateResult.Exception?.Message}");
        }

        if (!stateJwt.TryGetValue(
            GetAuthorizationUrlPlugin.JwtClaimNames.OneTimeRedirectUri,
            out string oneTimeRedirectUri) ||
            string.IsNullOrEmpty(oneTimeRedirectUri))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Embedded JWT specified in parameter '{InputParameterNames.State}' is missing required claim: {GetAuthorizationUrlPlugin.JwtClaimNames.OneTimeRedirectUri}");
        }

        outputs[OutputParameterNames.OneTimeRedirectUrl] = oneTimeRedirectUri;
    }
}