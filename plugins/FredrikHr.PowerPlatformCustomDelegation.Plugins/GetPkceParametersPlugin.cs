using System.Security.Cryptography;
using System.Text;

using Microsoft.IdentityModel.Tokens;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

namespace FredrikHr.PowerPlatformCustomDelegation.Plugins;

public sealed class GetPkceParametersPlugin : PluginBase, IPlugin
{
    internal const int PkceCodeVerifierByteLength = 96;
    internal const string PkceCodeChallengeMethodValue = "S256";
    internal const int NonceValueByteLength = 64;

    public GetPkceParametersPlugin() : base()
    {
        _ = typeof(Base64UrlEncoder);
    }

    internal static class OutputParameterNames
    {
        internal const string PkceCodeVerifier = nameof(PkceCodeVerifier);
        internal const string PkceCodeChallenge = nameof(PkceCodeChallenge);
        internal const string PkceCodeChallengeMethod = nameof(PkceCodeChallengeMethod);
        internal const string NonceParameter = nameof(NonceParameter);
    }

    protected override void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext>();
        ParameterCollection outputs = context.OutputParameters;

        using RandomNumberGenerator rng = RandomNumberGenerator.Create();
        using SHA256 sha256 = SHA256.Create();
        var pkceCodeVerifierBytes = new byte[PkceCodeVerifierByteLength];
        rng.GetBytes(pkceCodeVerifierBytes);
        string pkceCodeVerifier = Base64UrlEncoder.Encode(pkceCodeVerifierBytes);
        byte[] pkceCodeChallengeInput = Encoding.ASCII.GetBytes(pkceCodeVerifier);
        byte[] pkceCodeChallengeBytes = sha256.ComputeHash(pkceCodeChallengeInput);
        string pkceCodeChallenge = Base64UrlEncoder.Encode(pkceCodeChallengeBytes);

        var nonceValueBytes = new byte[NonceValueByteLength];
        rng.GetBytes(nonceValueBytes);
        string nonceValueString = Base64UrlEncoder.Encode(nonceValueBytes);

        outputs[OutputParameterNames.PkceCodeVerifier] = pkceCodeVerifier;
        outputs[OutputParameterNames.PkceCodeChallenge] = pkceCodeChallenge;
        outputs[OutputParameterNames.PkceCodeChallengeMethod] =
            PkceCodeChallengeMethodValue;
        outputs[OutputParameterNames.NonceParameter] = nonceValueString;
    }
}