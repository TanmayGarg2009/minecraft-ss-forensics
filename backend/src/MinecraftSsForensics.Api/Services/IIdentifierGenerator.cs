namespace MinecraftSsForensics.Api.Services;

public interface IIdentifierGenerator
{
    string GeneratePublicId();
    string GenerateDeletionKey();
    string HashDeletionKey(string deletionKey);
    bool VerifyDeletionKey(string deletionKey, string storedHash);
}
