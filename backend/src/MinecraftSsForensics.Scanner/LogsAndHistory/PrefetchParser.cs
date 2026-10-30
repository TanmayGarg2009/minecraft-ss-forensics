using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace MinecraftSsForensics.Scanner.LogsAndHistory;

public class PrefetchParseResult
{
    public bool Success { get; set; }
    public string ExecutableName { get; set; } = string.Empty;
    public int RunCount { get; set; }
    public List<DateTimeOffset> ExecutionTimestamps { get; set; } = new();
    public List<string> LoadedFilesAndModules { get; set; } = new();
    public string CompressionType { get; set; } = "None";
    public int SccaVersion { get; set; }
}

/// <summary>
/// Parser for Windows Prefetch (.pf) files on Windows 7, 8, 10, and 11.
/// Decompresses Windows 10/11 MAM-compressed prefetch files using ntdll!RtlDecompressBufferEx
/// with COMPRESSION_FORMAT_XPRESS_HUFF (0x0004).
/// Extracts run counters, the 8 execution timestamps, and loaded DLL/file dependencies.
/// </summary>
public static class PrefetchParser
{
    private const uint MAM_MAGIC = 0x044D414D; // "MAM\x04"
    private const uint SCCA_MAGIC = 0x41434353; // "SCCA"
    private const ushort COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004;

    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBufferEx(
        ushort CompressionFormat,
        byte[] UncompressedBuffer,
        int UncompressedBufferSize,
        byte[] CompressedBuffer,
        int CompressedBufferSize,
        out int FinalUncompressedSize,
        IntPtr WorkSpace);

    /// <summary>
    /// Parses a Windows Prefetch (.pf) file from disk or byte array.
    /// </summary>
    public static PrefetchParseResult ParsePrefetchFile(string filePath)
    {
        var result = new PrefetchParseResult();

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return result;

        try
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            return ParsePrefetchBytes(fileBytes);
        }
        catch
        {
            return result;
        }
    }

    /// <summary>
    /// Decompresses and parses Prefetch file bytes.
    /// </summary>
    public static PrefetchParseResult ParsePrefetchBytes(byte[] bytes)
    {
        var result = new PrefetchParseResult();
        if (bytes == null || bytes.Length < 16) return result;

        byte[] sccaBytes;
        uint headerMagic = BitConverter.ToUInt32(bytes, 0);

        if (headerMagic == MAM_MAGIC)
        {
            result.CompressionType = "MAM (XPRESS_HUFF)";
            if (bytes.Length < 8) return result;

            int uncompressedSize = BitConverter.ToInt32(bytes, 4);
            if (uncompressedSize <= 0 || uncompressedSize > 10 * 1024 * 1024) return result; // Sanity limit: 10MB

            if (!OperatingSystem.IsWindows())
            {
                // Decompression via ntdll requires Windows OS
                return result;
            }

            sccaBytes = new byte[uncompressedSize];
            byte[] compressedPayload = new byte[bytes.Length - 8];
            Buffer.BlockCopy(bytes, 8, compressedPayload, 0, compressedPayload.Length);

            int status = RtlDecompressBufferEx(
                COMPRESSION_FORMAT_XPRESS_HUFF,
                sccaBytes,
                uncompressedSize,
                compressedPayload,
                compressedPayload.Length,
                out int finalSize,
                IntPtr.Zero);

            if (status != 0 || finalSize <= 0)
            {
                return result; // Decompression failed
            }
        }
        else
        {
            result.CompressionType = "Uncompressed";
            sccaBytes = bytes;
        }

        if (sccaBytes.Length < 84) return result;

        // Verify SCCA header
        int sccaVersion = BitConverter.ToInt32(sccaBytes, 0);
        uint sccaSig = BitConverter.ToUInt32(sccaBytes, 4);

        if (sccaSig != SCCA_MAGIC) return result;

        result.SccaVersion = sccaVersion;
        result.Success = true;

        // Parse Executable Name at offset 16 (0x10) - 60 bytes (30 UTF-16 chars)
        if (sccaBytes.Length >= 76)
        {
            string exeName = Encoding.Unicode.GetString(sccaBytes, 16, 60).TrimEnd('\0');
            int nullIdx = exeName.IndexOf('\0');
            if (nullIdx >= 0) exeName = exeName[..nullIdx];
            result.ExecutableName = exeName;
        }

        // Parse Execution Timestamps and Run Counter based on Windows version
        if (sccaVersion == 30 && sccaBytes.Length >= 212) // Windows 10 & 11
        {
            // Run count is at offset 208 (0xD0)
            result.RunCount = BitConverter.ToInt32(sccaBytes, 208);

            // Up to 8 execution timestamps at offset 120 (0x78)
            for (int i = 0; i < 8; i++)
            {
                int tsOffset = 120 + (i * 8);
                if (tsOffset + 8 <= sccaBytes.Length)
                {
                    long fileTime = BitConverter.ToInt64(sccaBytes, tsOffset);
                    if (fileTime > 0)
                    {
                        try
                        {
                            result.ExecutionTimestamps.Add(DateTimeOffset.FromFileTime(fileTime));
                        }
                        catch { }
                    }
                }
            }

            // Filename strings table
            int stringsOffset = BitConverter.ToInt32(sccaBytes, 100); // 0x64
            int stringsLength = BitConverter.ToInt32(sccaBytes, 104); // 0x68

            if (stringsOffset > 0 && stringsLength > 0 && stringsOffset + stringsLength <= sccaBytes.Length)
            {
                string allStrings = Encoding.Unicode.GetString(sccaBytes, stringsOffset, stringsLength);
                string[] parts = allStrings.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                foreach (var p in parts)
                {
                    if (p.Length > 2) result.LoadedFilesAndModules.Add(p);
                }
            }
        }
        else if (sccaVersion == 26 && sccaBytes.Length >= 212) // Windows 8.1
        {
            result.RunCount = BitConverter.ToInt32(sccaBytes, 208);
            for (int i = 0; i < 8; i++)
            {
                int tsOffset = 128 + (i * 8);
                if (tsOffset + 8 <= sccaBytes.Length)
                {
                    long fileTime = BitConverter.ToInt64(sccaBytes, tsOffset);
                    if (fileTime > 0)
                    {
                        try { result.ExecutionTimestamps.Add(DateTimeOffset.FromFileTime(fileTime)); } catch { }
                    }
                }
            }
        }
        else if (sccaVersion == 23 && sccaBytes.Length >= 156) // Windows 7
        {
            result.RunCount = BitConverter.ToInt32(sccaBytes, 152);
            long fileTime = BitConverter.ToInt64(sccaBytes, 128);
            if (fileTime > 0)
            {
                try { result.ExecutionTimestamps.Add(DateTimeOffset.FromFileTime(fileTime)); } catch { }
            }
        }

        return result;
    }
}
