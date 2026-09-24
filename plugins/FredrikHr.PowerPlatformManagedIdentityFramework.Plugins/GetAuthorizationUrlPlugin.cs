using System.Security.Cryptography;

using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

public class GetAuthorizationUrlPlugin() : PluginBase(), IPlugin
{
    private const StringComparison OrdInv = StringComparison.OrdinalIgnoreCase;

    internal static class JwtClaimNames
    {
        internal const string OneTimeRedirectUri = "uri";
    }

    internal static class InputParameterNames
    {
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
        internal const string NonceParameter = nameof(NonceParameter);
    }

    private static readonly JsonWebTokenHandler JwtHandler = new();

    protected override void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        )
    {
        info ??= new(serviceProvider);
        var context = serviceProvider.Get<IPluginExecutionContext6>();

        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;

        _ = inputs.TryGetValue(
            InputParameterNames.Scopes,
            out string[]? scopes
            );
        scopes ??= [];
        if (!inputs.TryGetValue(
            InputParameterNames.OneTimeRedirectUri,
            out string oneTimeRedirectUri) ||
            string.IsNullOrEmpty(oneTimeRedirectUri))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.OneTimeRedirectUri}"
                );
        }
        if (!inputs.TryGetValue(
            InputParameterNames.PkceS256CodeChallenge,
            out string pkceCodeChallenge) ||
            string.IsNullOrEmpty(pkceCodeChallenge)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.PkceS256CodeChallenge}"
                );
        }

        var idpAuthorityInfo = serviceProvider.Get<IEnvironmentService>();
        Uri idpInstanceUri = idpAuthorityInfo.AzureAuthorityHost;
        string idpInstanceUrl = idpInstanceUri.ToString();
        var msalBuilder = ConfidentialClientApplicationBuilder
            .Create(MsalPluginUtility.FallbackClientId)
            .WithAuthority(
                idpInstanceUrl,
                context.TenantId
                )
            ;
        EncryptingCredentials keyVaultEncryptCreds = null!;

        SecurityTokenDescriptor stateJwtDesc = new()
        {
            Claims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                { JwtClaimNames.OneTimeRedirectUri, oneTimeRedirectUri },
            },
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase),
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
            .WithExtraQueryParameters(msalExtraParams)
            ;
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