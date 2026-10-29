using System.Collections.Concurrent;
using System.Text.Json;

namespace MinecraftSsForensics.Scanner.Verification;

public interface IVerificationCache
{
    bool TryGet(string hashKey, out ModVerificationResult result);
    void Set(string hashKey, ModVerificationResult result, TimeSpan? ttl = null);
    Task LoadFromDiskAsync(string cacheFilePath, CancellationToken ct = default);
    Task SaveToDiskAsync(string cacheFilePath, CancellationToken ct = default);
}

public class VerificationCache : IVerificationCache
{
    private class CacheEntry
    {
        public ModVerificationResult Result { get; set; } = new();
        public DateTime ExpiresAtUtc { get; set; }
    }

    private readonly ConcurrentDictionary<string, CacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _defaultTtl = TimeSpan.FromDays(7);

    public bool TryGet(string hashKey, out ModVerificationResult result)
    {
        result = null!;
        if (_entries.TryGetValue(hashKey, out var entry))
        {
            if (DateTime.UtcNow <= entry.ExpiresAtUtc)
            {
                result = entry.Result;
                result.IsCached = true;
                return true;
            }
            _entries.TryRemove(hashKey, out _);
        }
        return false;
    }

    public void Set(string hashKey, ModVerificationResult result, TimeSpan? ttl = null)
    {
        var entry = new CacheEntry
        {
            Result = result,
            ExpiresAtUtc = DateTime.UtcNow.Add(ttl ?? _defaultTtl)
        };
        _entries[hashKey] = entry;
    }

    public async Task LoadFromDiskAsync(string cacheFilePath, CancellationToken ct = default)
    {
        if (!File.Exists(cacheFilePath)) return;

        try
        {
            using var stream = File.OpenRead(cacheFilePath);
            var loaded = await JsonSerializer.DeserializeAsync<Dictionary<string, CacheEntry>>(stream, cancellationToken: ct);
            if (loaded != null)
            {
                var now = DateTime.UtcNow;
                foreach (var (k, v) in loaded)
                {
                    if (v.ExpiresAtUtc > now)
                    {
                        _entries[k] = v;
                    }
                }
            }
        }
        catch
        {
            // Cache load failure should never interrupt scanning
        }
    }

    public async Task SaveToDiskAsync(string cacheFilePath, CancellationToken ct = default)
    {
        try
        {
            string? dir = Path.GetDirectoryName(cacheFilePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            using var stream = File.Create(cacheFilePath);
            await JsonSerializer.SerializeAsync(stream, _entries, new JsonSerializerOptions { WriteIndented = true }, ct);
        }
        catch
        {
            // Non-critical background save failure
        }
    }
}
