namespace FredrikHr.PowerPlatformCustomDelegation.Common.JosePbes2;

public static class Pbes2Constants
{
    public const string Pbes2HmacSha256Aes128KeyWrap = "PBES2-HS256+A128KW";
    public const string Pbes2HmacSha384Aes192KeyWrap = "PBES2-HS384+A192KW";
    public const string Pbes2HmacSha512Aes256KeyWrap = "PBES2-HS512+A256KW";
    public const string Pbes2SaltInputHeaderParameter = "p2s";
    public const string Pbes2IterationCountHeaderParameter = "p2c";
    public const int Pbes2SaltInputMinByteLength = 8;
    public const int Pbes2RecommendedMinimumIterationCount = 1_000;
}