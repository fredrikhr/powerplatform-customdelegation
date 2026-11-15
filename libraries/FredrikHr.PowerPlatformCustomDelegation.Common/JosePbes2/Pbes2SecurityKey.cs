using System.Security.Cryptography;
using System.Text;

using Microsoft.IdentityModel.Tokens;

namespace FredrikHr.PowerPlatformCustomDelegation.Common.JosePbes2;

public class Pbes2SecurityKey : SecurityKey
{
    private readonly int _keySizeBits;
    private readonly byte[] _passwordBytes;
    private readonly byte[] _saltInputBytes;

    public override int KeySize => _keySizeBits;

    public ReadOnlySpan<byte> PasswordBytes => _passwordBytes;
    public ReadOnlySpan<byte> SaltInputBytes => _saltInputBytes;
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design",
        "CA1056: URI-like properties should not be strings",
        Justification = nameof(Base64UrlEncoder))]
    public string SaltInputBase64Url
        => field ??= Base64UrlEncoder.Encode(_saltInputBytes);
    public required int IterationCount { get; set; }

    public Pbes2SecurityKey(
        ReadOnlySpan<byte> passwordBytes,
        ReadOnlySpan<byte> saltInput) :
        this([..passwordBytes], [..saltInput], default)
    { }

    public Pbes2SecurityKey(string password, ReadOnlySpan<byte> saltInput)
        : this(Encoding.UTF8.GetBytes(password), [..saltInput], default)
    { }

    private Pbes2SecurityKey(byte[] passwordBytes, byte[] saltInputBytes, bool _)
    {
        _passwordBytes = passwordBytes;
        _saltInputBytes = saltInputBytes;
        _keySizeBits = _passwordBytes.Length * 8;
    }

    public Pbes2SecurityKey(string password, int saltInputByteLength = 16)
        : this(Encoding.UTF8.GetBytes(password), GenerateSaltInput(saltInputByteLength), default)
    { }

    public Pbes2SecurityKey(ReadOnlySpan<byte> passwordBytes, int saltInputByteLength = 16)
        : this([..passwordBytes], GenerateSaltInput(saltInputByteLength), default)
    { }

    private static byte[] GenerateSaltInput(int saltInputByteLength)
    {
        byte[] saltInputBytes = new byte[saltInputByteLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(saltInputBytes);
        return saltInputBytes;
    }
}