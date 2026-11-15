using System.Security.Cryptography;

using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault.Certificates;

using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformCustomDelegation.Common;
using FredrikHr.PowerPlatformCustomDelegation.Common.JosePbes2;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;

namespace FredrikHr.PowerPlatformCustomDelegation.Plugins;

public class GetAuthorizationUrlPlugin() : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;

    internal static class JwtClaimNames
    {
        internal const string OneTimeRedirectUri = "uri";
    }

    internal static class InputParameterNames
    {
        internal const string Application = nameof(Application);
        internal const string ClientConfiguration = nameof(ClientConfiguration);
        internal const string ClientCredentialsSource = nameof(ClientCredentialsSource);
        internal const string LoginHint = nameof(LoginHint);
        internal const string Prompt = nameof(Prompt);
        internal const string Scopes = nameof(Scopes);
        internal const string ResponseMode = nameof(ResponseMode);
        internal const string PkceS256CodeChallenge = nameof(PkceS256CodeChallenge);
        internal const string CommonRedirectUri = nameof(CommonRedirectUri);
        internal const string OneTimeRedirectUri = nameof(OneTimeRedirectUri);
        internal const string IncludeIdToken = nameof(IncludeIdToken);
        internal const string NonceParameter = nameof(NonceParameter);
    }

    internal static class OutputParameterNames
    {
        internal const string AuthorizationRequestUrl = nameof(AuthorizationRequestUrl);
        internal const string State = nameof(State);
        internal const string NonceParameter = nameof(NonceParameter);
    }

    private static readonly JsonWebTokenHandler JwtHandler = new();
    private static readonly Pbes2CryptoProviderFactory Pbes2CryptoProviderFactory = new();

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

    private static void ExecuteCoreImpl(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info)
    {
        info ??= new(serviceProvider);
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        PowerPlatformFicTokenCredential azureCredential = new(serviceProvider);
        AzureUtility azureUtility = new(azureCredential);
        MsalPluginUtility msalUtility = new(
            serviceProvider,
            info,
            azureUtility,
            InputParameterNames.Application,
            InputParameterNames.ClientCredentialsSource,
            InputParameterNames.ClientConfiguration);

        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;

        _ = inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[]? scopes);
        scopes ??= [];
        if (!inputs.TryGetValue(
            InputParameterNames.OneTimeRedirectUri,
            out string oneTimeRedirectUri) ||
            string.IsNullOrEmpty(oneTimeRedirectUri))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.OneTimeRedirectUri}");
        }
        if (!inputs.TryGetValue(
            InputParameterNames.PkceS256CodeChallenge,
            out string pkceCodeChallenge) ||
            string.IsNullOrEmpty(pkceCodeChallenge))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.PkceS256CodeChallenge}");
        }

        KeyVaultBackedCredentialsSource? keyVaultEncryptCredsSource = msalUtility.ClientCredentialsSource;
        if (keyVaultEncryptCredsSource is not { KeyVaultObjectResourceIdentifier: ResourceIdentifier kvObjArmId })
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or invalid required parameter specifying the source of the encrypting credentials.");
        }
        KeyVaultDataAccessEvaluator kvAccessEval = new(
            azureUtility.ArmClient,
            kvObjArmId,
            context.UserAzureActiveDirectoryObjectId
            );
        KeyVaultDataAccessPermisions kvAccessPerms = kvAccessEval
            .EvaluateAccessAsync()
            .GetAwaiter().GetResult();
        switch (keyVaultEncryptCredsSource.KeyVaultObjectType)
        {
            case keytype.Secret:
                if (kvAccessPerms.HasFlag(KeyVaultDataAccessPermisions.GetSecret))
                    break;
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.Forbidden,
                    message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required role assignment to use the specified Key Vault Secret as a credential for encryption. User is not authorized for the Get Secret Key Vault action on the specified secret.");
            case keytype.Certificate:
            case keytype.CertificateWithX5c:
                if (kvAccessPerms.HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties))
                    break;
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.Forbidden,
                    message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required role assignment to use the specified Key Vault Certificate as a credential for encryption. User is not authorized either for the Get Certificate Properties action on the specified certificate.");
        }

        msalUtility.EnsureMsalClientOptionsAvailable();
        var msalBuilder = msalUtility.CreateMsalClientBuilder();
        Dictionary<string, object> headerClaims =
            new(comparer: StringComparer.OrdinalIgnoreCase);
        EncryptingCredentials keyVaultEncryptCreds = keyVaultEncryptCredsSource switch
        {
            {
                KeyVaultObjectType: keytype.Secret,
                KeyVaultSecretIdentifier: KeyVaultSecretIdentifier kvSecretUriId
            } => GetEncryptingCredentialsFromSecret(azureCredential, kvSecretUriId, headerClaims)
                .GetAwaiter().GetResult(),
            {
                KeyVaultObjectType: keytype.Certificate or keytype.CertificateWithX5c,
                KeyVaultCertificateIdentifier: KeyVaultCertificateIdentifier kvCertUriId
            } => GetEncryptingCredentialsFromCertificate(azureCredential, kvCertUriId)
                .GetAwaiter().GetResult(),
            _ => throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or invalid required parameter specifying the source of the encrypting credentials."),
        };

        static async Task<EncryptingCredentials> GetEncryptingCredentialsFromSecret(
            TokenCredential azCreds,
            KeyVaultSecretIdentifier kvSecretUriId,
            Dictionary<string, object> headerClaims)
        {
            KeyVaultSecret kvSecret = await KeyVaultPluginUtility
                .GetKeyVaultSecretAsync(azCreds, kvSecretUriId)
                .ConfigureAwait(continueOnCapturedContext: false);
            Pbes2SecurityKey kvSecKey = new(kvSecret.Value, saltInputByteLength: 16)
            {
                KeyId = kvSecret.Id.ToString(),
                IterationCount = 100_000,
                CryptoProviderFactory = Pbes2CryptoProviderFactory,
            };
            headerClaims[Pbes2Constants.Pbes2SaltInputHeaderParameter] =
                kvSecKey.SaltInputBase64Url;
            headerClaims[Pbes2Constants.Pbes2IterationCountHeaderParameter] =
                kvSecKey.IterationCount;
            return new EncryptingCredentials(
                kvSecKey,
                alg: Pbes2Constants.Pbes2HmacSha512Aes256KeyWrap,
                enc: SecurityAlgorithms.Aes256CbcHmacSha512)
            {
                CryptoProviderFactory = Pbes2CryptoProviderFactory,
            };
        }

        static async Task<EncryptingCredentials> GetEncryptingCredentialsFromCertificate(
            TokenCredential azCreds,
            KeyVaultCertificateIdentifier kvCertUriId)
        {
            KeyVaultCertificate kvCertData = await
                KeyVaultPluginUtility.GetKeyVaultCertificateAsync(
                    azCreds,
                    kvCertUriId)
                    .ConfigureAwait(continueOnCapturedContext: false);
            return new EncryptingCredentials(
                KeyVaultPluginUtility.GetKeyVaultPublicX509SecurityKey(kvCertData),
                alg: SecurityAlgorithms.RsaOAEP,
                enc: SecurityAlgorithms.Aes256CbcHmacSha512);
        }

        SecurityTokenDescriptor stateJwtDesc = new()
        {
            Claims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { JwtClaimNames.OneTimeRedirectUri, oneTimeRedirectUri },
            },
            AdditionalHeaderClaims = headerClaims,
            EncryptingCredentials = keyVaultEncryptCreds,
            IncludeKeyIdInHeader = true,
        };
        if (inputs.TryGetValue(
            InputParameterNames.CommonRedirectUri,
            out string? commonRedirectUri) &&
            !string.IsNullOrEmpty(commonRedirectUri))
        {
            msalBuilder = msalBuilder.WithRedirectUri(commonRedirectUri);
        }

        string stateQueryParam = JwtHandler.CreateToken(stateJwtDesc);
        outputs[OutputParameterNames.State] = stateQueryParam;
        Dictionary<string, string> msalExtraParams = new(StringComparer.OrdinalIgnoreCase)
        {
            { "state", stateQueryParam },
            { "code_challenge", pkceCodeChallenge },
            { "code_challenge_method", "S256" },
        };
        if (inputs.TryGetValue(
            InputParameterNames.ResponseMode,
            out string responseMode) &&
            !string.IsNullOrEmpty(responseMode))
        {
            msalExtraParams["response_mode"] = responseMode;
        }
        if (!inputs.TryGetValue(
            InputParameterNames.IncludeIdToken,
            out bool includeIdToken
            ))
        {
            includeIdToken = false;
        }
        if (includeIdToken)
        {
            if (!inputs.TryGetValue(
                InputParameterNames.NonceParameter,
                out string nonceValue
                ))
            {
                using RandomNumberGenerator rng = RandomNumberGenerator.Create();
                byte[] nonceBytes = new byte[64];
                rng.GetBytes(nonceBytes);
                nonceValue = Base64UrlEncoder.Encode(nonceBytes);
            }

            msalExtraParams["nonce"] = nonceValue;
            outputs[OutputParameterNames.NonceParameter] = nonceValue;

            if (!scopes.Contains("openid", StringComparer.Ordinal))
            {
                scopes = [
                    "openid",
                    ..scopes,
                ];
            }
        }

        IConfidentialClientApplication msalClient = msalBuilder.Build();
        var msalAuthReqBuilder = msalClient.GetAuthorizationRequestUrl(scopes)
            .WithExtraQueryParameters(msalExtraParams);
        if (inputs.TryGetValue(
            InputParameterNames.LoginHint,
            out string loginHint) &&
            !string.IsNullOrEmpty(loginHint))
        {
            msalAuthReqBuilder = msalAuthReqBuilder
                .WithLoginHint(loginHint);
        }
        if (inputs.TryGetValue(
            InputParameterNames.Prompt,
            out string promptBehavior) &&
            !string.IsNullOrEmpty(promptBehavior))
        {
            msalAuthReqBuilder =
                "select_account".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.SelectAccount)
                : "login".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.ForceLogin)
                : "no_prompt".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.NoPrompt)
                : "consent".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Consent)
                : "attempt_none".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Never)
                : "none".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Never)
                : "create".Equals(promptBehavior, OrdInv)
                ? msalAuthReqBuilder.WithPrompt(Prompt.Create)
                : msalAuthReqBuilder; // Don't do anything if not recognized.
        }
        Uri msalAuthReqUri = msalAuthReqBuilder
            .ExecuteAsync().GetAwaiter().GetResult();

        outputs[OutputParameterNames.AuthorizationRequestUrl] =
            msalAuthReqUri.ToString();
    }
}