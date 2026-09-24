using Microsoft.Identity.Client;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformManagedIdentityFramework.Common;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

public sealed class ValidateJsonWebTokenPlugin : PluginBase, IPlugin
{
    internal static class InputParameterNames
    {
        internal const string TenantId = nameof(TenantId);
        internal const string JsonWebToken = nameof(JsonWebToken);
    }

    internal static class OutputParameterNames
    {
        internal const string JsonWebTokenInfo = nameof(JsonWebTokenInfo);
        internal const string JsonWebToken = nameof(JsonWebToken);
    }

    private static readonly JsonWebTokenHandler JwtHandler = new();

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1031: Do not catch general exception types",
        Justification = nameof(ITracingService)
        )]
    protected override void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        )
    {
        info ??= new(serviceProvider);
        var context = serviceProvider.Get<IPluginExecutionContext6>();
        ParameterCollection inputs = context.InputParameters;
        ParameterCollection outputs = context.OutputParameters;

        if (!inputs.TryGetValue(
            InputParameterNames.JsonWebToken,
            out string jwtBase64Url) ||
            string.IsNullOrEmpty(jwtBase64Url)
            )
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing or empty required parameter: {InputParameterNames.JsonWebToken}"
                );
        }


        if (!inputs.TryGetValue(
            InputParameterNames.TenantId,
            out string tenantId) ||
            string.IsNullOrEmpty(tenantId)
            )
        {
            tenantId = context.TenantId.ToString();
        }

        var idpAuthorityInfo = serviceProvider.Get<IEnvironmentService>();
        Uri idpInstanceUri = idpAuthorityInfo.AzureAuthorityHost;
        string idpInstanceUrl = idpInstanceUri.ToString();

        IPublicClientApplication msalClient = PublicClientApplicationBuilder
            .Create(MsalPluginUtility.FallbackClientId)
            .WithAuthority(
                idpInstanceUrl,
                tenantId,
                validateAuthority: true
                )
            .Build();
        ConfigurationManager<OpenIdConnectConfiguration> jwtConfigMgr = new(
            $"{msalClient.Authority}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever()
            );

        TokenValidationParameters jwtValidationParams = new()
        {
            ConfigurationManager = jwtConfigMgr,
            ValidateIssuerSigningKey = true,
            ValidTypes = [JwtConstants.TokenType],
#pragma warning disable CA5404 // Do not disable token validation checks
            ValidateAudience = false,
#pragma warning restore CA5404 // Do not disable token validation checks
            ValidateLifetime = true,
            RequireAudience = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
        };
        TokenValidationResult jwtValidationResult = JwtHandler
            .ValidateTokenAsync(jwtBase64Url, jwtValidationParams)
            .GetAwaiter().GetResult();
        if (!jwtValidationResult.IsValid)
        {
            info.TracingService.Trace(
                "JWT Validation failed: {0}",
                jwtValidationResult.Exception
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Provided JWT is not valid: {jwtValidationResult.Exception.Message}"
                );
        }
        var jwtModel = (JsonWebToken)jwtValidationResult.SecurityToken;

        Entity jwtInfoEntity = new()
        {
            Attributes =
            {
                { nameof(jwtModel.Actor), jwtModel.Actor },
                { nameof(jwtModel.Alg), jwtModel.Alg },
                { nameof(jwtModel.Audiences), jwtModel.Audiences.ToArray() },
                { nameof(jwtModel.Azp), jwtModel.Azp },
                { nameof(jwtModel.Cty), jwtModel.Cty },
                { nameof(jwtModel.Enc), jwtModel.Enc },
                { nameof(jwtModel.Id), jwtModel.Id },
                { nameof(jwtModel.IsEncrypted), jwtModel.IsEncrypted },
                { nameof(jwtModel.IsSigned), jwtModel.IsSigned },
                { nameof(jwtModel.IssuedAt), jwtModel.IssuedAt },
                { nameof(jwtModel.Issuer), jwtModel.Issuer },
                { nameof(jwtModel.Kid), jwtModel.Kid },
                { nameof(jwtModel.Subject), jwtModel.Subject },
                { nameof(jwtModel.Typ), jwtModel.Typ },
                { nameof(jwtModel.ValidFrom), jwtModel.ValidFrom },
                { nameof(jwtModel.ValidTo), jwtModel.ValidTo },
                { nameof(jwtModel.X5t), jwtModel.X5t },
                { nameof(jwtModel.Zip), jwtModel.Zip },
            },
        };

        outputs[OutputParameterNames.JsonWebTokenInfo] = jwtInfoEntity;
        outputs[OutputParameterNames.JsonWebToken] =
            JwtUtility.GetJwtEntity(jwtBase64Url);
    }
}