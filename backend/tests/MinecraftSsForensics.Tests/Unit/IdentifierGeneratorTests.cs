using FluentAssertions;
using MinecraftSsForensics.Api.Services;
using Xunit;

namespace MinecraftSsForensics.Tests.Unit;

public class IdentifierGeneratorTests
{
    private readonly SecureIdentifierGenerator _generator = new();

    [Fact]
    public void GeneratePublicId_ShouldProduceUnguessablePrefixedIdWithHighEntropy()
    {
        // Act
        var id = _generator.GeneratePublicId();

        // Assert
        id.Should().NotBeNullOrWhiteSpace();
        id.Should().StartWith("mc_");
        id.Length.Should().BeGreaterThan(15);
    }

    [Fact]
    public void GeneratePublicId_ShouldGenerateUniqueIdentifiers()
    {
        // Act
        var set = new HashSet<string>();
        for (int i = 0; i < 500; i++)
        {
            var id = _generator.GeneratePublicId();
            set.Add(id).Should().BeTrue("every generated identifier must be unique");
        }
    }

    [Fact]
    public void GenerateDeletionKey_ShouldGenerateSecurePrefixedKey()
    {
        // Act
        var key = _generator.GenerateDeletionKey();

        // Assert
        key.Should().StartWith("del_");
        key.Length.Should().Be(68); // "del_" + 64 hex chars (32 bytes)
    }

    [Fact]
    public void HashDeletionKey_And_VerifyDeletionKey_ShouldValidateLegitimateKey()
    {
        // Arrange
        var key = _generator.GenerateDeletionKey();

        // Act
        var hash = _generator.HashDeletionKey(key);
        var isValid = _generator.VerifyDeletionKey(key, hash);

        // Assert
        hash.Should().NotBeNullOrWhiteSpace();
        hash.Should().NotBe(key, "stored hash must never be identical to plaintext deletion key");
        isValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyDeletionKey_ShouldRejectIncorrectOrTamperedKey()
    {
        // Arrange
        var key = _generator.GenerateDeletionKey();
        var tamperedKey = key + "tampered";
        var hash = _generator.HashDeletionKey(key);

        // Act
        var isValid = _generator.VerifyDeletionKey(tamperedKey, hash);
        var isNullValid = _generator.VerifyDeletionKey("", hash);

        // Assert
        isValid.Should().BeFalse();
        isNullValid.Should().BeFalse();
    }
}
