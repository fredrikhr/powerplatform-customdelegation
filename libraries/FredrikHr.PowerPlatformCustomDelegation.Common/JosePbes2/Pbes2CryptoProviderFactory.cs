using Microsoft.IdentityModel.Tokens;

namespace FredrikHr.PowerPlatformCustomDelegation.Common.JosePbes2;

using static Pbes2Constants;

public class Pbes2CryptoProviderFactory : CryptoProviderFactory
{
    private const StringComparison OrdIgn = StringComparison.OrdinalIgnoreCase;
    public const string Pbes2HmacSha256Aes128KeyWrap = "PBES2-HS256+A128KW";
    public const string Pbes2HmacSha384Aes192KeyWrap = "PBES2-HS384+A192KW";
    public const string Pbes2HmacSha512Aes256KeyWrap = "PBES2-HS512+A256KW";

    public int MinimumIterationCount { get; set; } = Pbes2RecommendedMinimumIterationCount;
    public int MaximumIterationCount { get; set; } = 1_000_000;

    public static bool IsSupportedPbes2KeyWrapAlgorithm(
        string algorithm,
        SecurityKey? key)
    {
        bool isValidAlgorithm =
            Pbes2HmacSha256Aes128KeyWrap.Equals(algorithm, OrdIgn) ||
            Pbes2HmacSha384Aes192KeyWrap.Equals(algorithm, OrdIgn) ||
            Pbes2HmacSha512Aes256KeyWrap.Equals(algorithm, OrdIgn);
        bool isValidKey = key is null or Pbes2SecurityKey;
        return isValidAlgorithm && isValidKey;
    }

    public override bool IsSupportedAlgorithm(string algorithm)
    {
        return IsSupportedPbes2KeyWrapAlgorithm(algorithm, key: null) ||
            base.IsSupportedAlgorithm(algorithm);
    }

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
    {
        return IsSupportedPbes2KeyWrapAlgorithm(algorithm, key) ||
            base.IsSupportedAlgorithm(algorithm, key);
    }

    public override KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm)
    {
        return IsSupportedPbes2KeyWrapAlgorithm(algorithm, key)
            ? new Pbes2KeyWrapProvider((Pbes2SecurityKey)key, algorithm)
            {
                MinimumIterationCount = MinimumIterationCount,
                MaximumIterationCount = MaximumIterationCount,
            }
            : base.CreateKeyWrapProvider(key, algorithm);
    }

    public override KeyWrapProvider CreateKeyWrapProviderForUnwrap(SecurityKey key, string algorithm)
    {
        return IsSupportedPbes2KeyWrapAlgorithm(algorithm, key)
            ? new Pbes2KeyWrapProvider((Pbes2SecurityKey)key, algorithm)
            {
                MinimumIterationCount = MinimumIterationCount,
                MaximumIterationCount = MaximumIterationCount,
            }
            : base.CreateKeyWrapProviderForUnwrap(key, algorithm);
    }
}