using System.Security.Cryptography;
using System.Text;

using Microsoft.IdentityModel.Tokens;

namespace FredrikHr.PowerPlatformCustomDelegation.Common.JosePbes2;

using static Pbes2Constants;

public class Pbes2KeyWrapProvider : KeyWrapProvider
{
    private readonly string _algorithm;
    private readonly byte[] _algorithmBytes;
    private readonly CryptoProviderFactory _cryptoProviderFactory;
    private readonly Pbes2SecurityKey _key;
    private readonly int _pbkdf2ByteCount;
    private readonly HashAlgorithmName _hashAlgorithmName;
    private readonly string _keyWrapAlgorithm;

    public Pbes2KeyWrapProvider(Pbes2SecurityKey key, string algorithm) :
        base()
    {
        const StringComparison ord = StringComparison.Ordinal;
        switch (algorithm)
        {
            case string _
            when Pbes2HmacSha256Aes128KeyWrap.Equals(algorithm, ord):
                _hashAlgorithmName = HashAlgorithmName.SHA256;
                _pbkdf2ByteCount = 16;
                _keyWrapAlgorithm = SecurityAlgorithms.Aes128KW;
                break;
            case string _
            when Pbes2HmacSha384Aes192KeyWrap.Equals(algorithm, ord):
                _hashAlgorithmName = HashAlgorithmName.SHA384;
                _pbkdf2ByteCount = 24;
                _keyWrapAlgorithm = SecurityAlgorithms.Aes192KW;
                break;
            case string _
            when Pbes2HmacSha512Aes256KeyWrap.Equals(algorithm, ord):
                _hashAlgorithmName = HashAlgorithmName.SHA512;
                _pbkdf2ByteCount = 32;
                _keyWrapAlgorithm = SecurityAlgorithms.Aes256KW;
                break;
            default:
                throw new NotSupportedException($"Specified algorithm '{algorithm}' is not an acceptable PBES2 Key wrapping algorithm.");
        }

        _algorithm = algorithm;
        _key = key ?? throw new ArgumentNullException(nameof(key));

        _algorithmBytes = Encoding.UTF8.GetBytes(algorithm);
        _cryptoProviderFactory = key.CryptoProviderFactory ??
            CryptoProviderFactory.Default;
    }

    public override SecurityKey Key => _key;
    public override string Algorithm => _algorithm;

    public override string? Context { get; set; }

    public int MinimumIterationCount { get; set; } = Pbes2RecommendedMinimumIterationCount;

    public int MaximumIterationCount { get; set; } = 1_000_000;

    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Security",
        "CA5379: Ensure Key Derivation Function algorithm is sufficiently strong",
        Justification = "RFC7518, Section 4.8")]
    private SymmetricSecurityKey CreateDerivedKeyWrapKey()
    {
        int iterations = GetAndValidateIterationCount();
        byte[] fullSaltBytes = GetAndValidateSaltInput();
        byte[] passwordBytes = [.._key.PasswordBytes];
        byte[] kwKeyBytes;
        using Rfc2898DeriveBytes pbkdf2 = new(
            passwordBytes,
            fullSaltBytes,
            iterations,
            _hashAlgorithmName);
        kwKeyBytes = pbkdf2.GetBytes(_pbkdf2ByteCount);
        try
        {
            return new SymmetricSecurityKey(kwKeyBytes)
            { CryptoProviderFactory = _cryptoProviderFactory };
        }
        finally
        {
            passwordBytes.AsSpan().Clear();
            fullSaltBytes.AsSpan().Clear();
            kwKeyBytes.AsSpan().Clear();
        }
    }

    public override byte[] WrapKey(byte[] keyBytes)
    {
        SymmetricSecurityKey kwKey = CreateDerivedKeyWrapKey();
        using KeyWrapProvider kwProvider = _cryptoProviderFactory
            .CreateKeyWrapProvider(kwKey, _keyWrapAlgorithm);
        return kwProvider.WrapKey(keyBytes);
    }

    public override byte[] UnwrapKey(byte[] keyBytes)
    {
        SymmetricSecurityKey kwKey = CreateDerivedKeyWrapKey();
        using KeyWrapProvider kwProvider = _cryptoProviderFactory
            .CreateKeyWrapProviderForUnwrap(kwKey, _keyWrapAlgorithm);
        return kwProvider.UnwrapKey(keyBytes);
    }

    private int GetAndValidateIterationCount()
    {
        int iterations = _key.IterationCount;
        return iterations < MinimumIterationCount
            ? throw new InvalidOperationException($"Provided PBES2 security key specifies an iteration count of {iterations} which is less than the configured minimum iteration count {MinimumIterationCount}.")
            : iterations > MaximumIterationCount
            ? throw new InvalidOperationException($"Provided PBES2 security key specifies an iteration count of {iterations} which is greater than the configured maximum iteration count {MaximumIterationCount}.")
            : iterations;
    }

    private byte[] GetAndValidateSaltInput()
    {
        ReadOnlySpan<byte> saltInputBytes = _key.SaltInputBytes;
        return saltInputBytes.Length < Pbes2SaltInputMinByteLength
            ? throw new InvalidOperationException($"Provided PBES2 Salt Input is too short. A Salt Input value containing {Pbes2SaltInputMinByteLength} or more octets must be used.")
            : [.._algorithmBytes, 0, ..saltInputBytes];
    }

    protected override void Dispose(bool disposing) { }
}