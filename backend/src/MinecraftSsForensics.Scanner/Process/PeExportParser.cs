using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace MinecraftSsForensics.Scanner.Process;

/// <summary>
/// Status codes returned by the hardened PE export directory parser.
/// </summary>
public enum PeExportParseStatus
{
    Success,
    FileNotFound,
    FileTooSmall,
    InvalidDosHeader,
    InvalidPeOffset,
    InvalidPeSignature,
    UnsupportedArchitecture,
    InvalidOptionalHeader,
    NoExportDirectory,
    OutOfBoundsExportDirectory,
    InvalidSectionTable,
    MalformedExportTable,
    VirtualZeroFillRegion,
    IoError
}

/// <summary>
/// Structured result of PE export table inspection.
/// </summary>
public class PeExportParseResult
{
    public PeExportParseStatus Status { get; set; } = PeExportParseStatus.Success;
    public string DiagnosticMessage { get; set; } = string.Empty;
    public List<string> ExportedNames { get; set; } = new();
    public int NumberOfNamesReported { get; set; }
    public bool HasRecognizedJavaExports { get; set; }
    public bool HasJniOnLoad { get; set; }
    public bool HasForwarders { get; set; }
    public List<string> Forwarders { get; set; } = new();
    public string MatchedJavaSymbol { get; set; } = string.Empty;
}

/// <summary>
/// Hardened, safe PE (Portable Executable) export directory parser.
/// Enforces checked arithmetic, file-boundary validation, virtual zero-fill rejection,
/// bounded allocations, and returns structured diagnostics without unhandled exceptions.
/// </summary>
public static class PeExportParser
{
    private const ushort DosSignature = 0x5A4D; // "MZ"
    private const uint PeSignature = 0x00004550; // "PE\0\0"
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;

    private const int MaxExportsToRead = 500;
    private const int MaxNameLength = 256;

    /// <summary>
    /// Checks whether the given PE file exports recognized Java Native Interface (JNI) or JNA symbols.
    /// </summary>
    public static bool HasRecognizedJavaExports(string filePath, out string matchedSymbol)
    {
        var result = ParseExports(filePath, maxExportsToRead: 100);
        matchedSymbol = result.MatchedJavaSymbol;
        return result.HasRecognizedJavaExports;
    }

    /// <summary>
    /// Parses exported function names from a PE binary, returning structured diagnostics.
    /// </summary>
    public static PeExportParseResult ParseExports(string filePath, int maxExportsToRead = 100)
    {
        var result = new PeExportParseResult();

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            result.Status = PeExportParseStatus.FileNotFound;
            result.DiagnosticMessage = "Target file does not exist or path is invalid.";
            return result;
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            long fileLength = fs.Length;

            if (fileLength < 0x40)
            {
                result.Status = PeExportParseStatus.FileTooSmall;
                result.DiagnosticMessage = $"File size ({fileLength} bytes) is smaller than minimum DOS header size.";
                return result;
            }

            using var reader = new BinaryReader(fs, Encoding.ASCII);

            // 1. DOS Header Validation
            ushort dosSig = reader.ReadUInt16();
            if (dosSig != DosSignature)
            {
                result.Status = PeExportParseStatus.InvalidDosHeader;
                result.DiagnosticMessage = $"Invalid DOS header signature (0x{dosSig:X4}). Expected 'MZ' (0x5A4D).";
                return result;
            }

            fs.Seek(0x3C, SeekOrigin.Begin);
            int e_lfanew = reader.ReadInt32();

            // e_lfanew must be positive and fit within the file with at least PE signature + File Header
            if (e_lfanew < 0x40 || e_lfanew > fileLength - 24)
            {
                result.Status = PeExportParseStatus.InvalidPeOffset;
                result.DiagnosticMessage = $"Invalid e_lfanew offset (0x{e_lfanew:X}). Out of file bounds.";
                return result;
            }

            // 2. PE Header Validation
            fs.Seek(e_lfanew, SeekOrigin.Begin);
            uint peSig = reader.ReadUInt32();
            if (peSig != PeSignature)
            {
                result.Status = PeExportParseStatus.InvalidPeSignature;
                result.DiagnosticMessage = $"Invalid PE signature (0x{peSig:X8}). Expected 'PE\\0\\0'.";
                return result;
            }

            // File Header
            fs.Seek(e_lfanew + 4, SeekOrigin.Begin);
            ushort machine = reader.ReadUInt16(); // e.g. 0x8664 (x64) or 0x014c (x86)
            ushort numberOfSections = reader.ReadUInt16();
            fs.Seek(e_lfanew + 4 + 16, SeekOrigin.Begin); // Pointer to SizeOfOptionalHeader
            ushort sizeOfOptionalHeader = reader.ReadUInt16();

            int optionalHeaderOffset = checked(e_lfanew + 24);
            if (optionalHeaderOffset + sizeOfOptionalHeader > fileLength)
            {
                result.Status = PeExportParseStatus.InvalidOptionalHeader;
                result.DiagnosticMessage = "Optional header extends past physical file boundary.";
                return result;
            }

            // 3. Optional Header Validation
            fs.Seek(optionalHeaderOffset, SeekOrigin.Begin);
            ushort magic = reader.ReadUInt16();

            // Validate Architecture Consistency between File Header Machine and Optional Header Magic
            if ((machine == 0x8664 || machine == 0xAA64) && magic != Pe32PlusMagic)
            {
                result.Status = PeExportParseStatus.UnsupportedArchitecture;
                result.DiagnosticMessage = $"Architecture mismatch: 64-bit machine (0x{machine:X4}) with non-PE32+ optional header magic (0x{magic:X4}).";
                return result;
            }
            if (machine == 0x014C && magic != Pe32Magic)
            {
                result.Status = PeExportParseStatus.UnsupportedArchitecture;
                result.DiagnosticMessage = $"Architecture mismatch: 32-bit machine (0x014C) with non-PE32 optional header magic (0x{magic:X4}).";
                return result;
            }

            int exportDirDataOffset;
            if (magic == Pe32PlusMagic) // 64-bit PE+
            {
                exportDirDataOffset = checked(optionalHeaderOffset + 112); // DataDirectory[0] (Export Table)
            }
            else if (magic == Pe32Magic) // 32-bit PE
            {
                exportDirDataOffset = checked(optionalHeaderOffset + 96);
            }
            else
            {
                result.Status = PeExportParseStatus.UnsupportedArchitecture;
                result.DiagnosticMessage = $"Unsupported PE optional header magic 0x{magic:X4}.";
                return result;
            }

            if (exportDirDataOffset + 8 > fileLength)
            {
                result.Status = PeExportParseStatus.InvalidOptionalHeader;
                result.DiagnosticMessage = "Data directory table extends past file boundary.";
                return result;
            }

            fs.Seek(exportDirDataOffset, SeekOrigin.Begin);
            uint exportRva = reader.ReadUInt32();
            uint exportSize = reader.ReadUInt32();

            if (exportRva == 0 || exportSize == 0)
            {
                result.Status = PeExportParseStatus.NoExportDirectory;
                result.DiagnosticMessage = "Binary does not contain an export directory (RVA=0 or Size=0).";
                return result;
            }

            // 4. Section Table Parsing with Checked Arithmetic
            int sectionHeadersOffset = checked(optionalHeaderOffset + sizeOfOptionalHeader);
            if (checked(sectionHeadersOffset + (numberOfSections * 40)) > fileLength)
            {
                result.Status = PeExportParseStatus.InvalidSectionTable;
                result.DiagnosticMessage = "Section headers table extends past file boundary.";
                return result;
            }

            var sections = new List<(uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize)>(numberOfSections);

            for (int i = 0; i < numberOfSections; i++)
            {
                long secPos = checked(sectionHeadersOffset + (i * 40));
                fs.Seek(secPos + 8, SeekOrigin.Begin);
                uint vSize = reader.ReadUInt32();
                uint vAddr = reader.ReadUInt32();
                uint rawSize = reader.ReadUInt32();
                uint rawOffset = reader.ReadUInt32();

                if (rawOffset > 0 && rawSize > 0 && checked(rawOffset + rawSize) > fileLength)
                {
                    result.Status = PeExportParseStatus.InvalidSectionTable;
                    result.DiagnosticMessage = $"Section {i} raw data extends past physical file boundary.";
                    return result;
                }

                sections.Add((vAddr, vSize, rawOffset, rawSize));
            }

            // Map Export Directory RVA to File Offset
            long exportFileOffset = RvaToFileOffset(exportRva, sections, fileLength, out bool isZeroFill);
            if (isZeroFill)
            {
                result.Status = PeExportParseStatus.VirtualZeroFillRegion;
                result.DiagnosticMessage = "Export directory points into uninitialized virtual zero-fill memory.";
                return result;
            }

            if (exportFileOffset < 0 || checked(exportFileOffset + 40) > fileLength)
            {
                result.Status = PeExportParseStatus.OutOfBoundsExportDirectory;
                result.DiagnosticMessage = $"Export directory file offset (0x{exportFileOffset:X}) is out of file bounds.";
                return result;
            }

            // 5. Read Export Directory Table (IMAGE_EXPORT_DIRECTORY)
            // Offset 20: NumberOfFunctions (DWORD)
            // Offset 24: NumberOfNames (DWORD)
            // Offset 28: AddressOfFunctions (DWORD RVA)
            // Offset 32: AddressOfNames (DWORD RVA)
            // Offset 36: AddressOfNameOrdinals (DWORD RVA)
            fs.Seek(checked(exportFileOffset + 20), SeekOrigin.Begin);
            uint numberOfFunctions = reader.ReadUInt32();
            uint numberOfNames = reader.ReadUInt32();
            uint addressOfFunctionsRva = reader.ReadUInt32();
            uint addressOfNamesRva = reader.ReadUInt32();
            uint addressOfNameOrdinalsRva = reader.ReadUInt32();

            result.NumberOfNamesReported = (int)Math.Min(numberOfNames, int.MaxValue);

            long addressOfNamesOffset = RvaToFileOffset(addressOfNamesRva, sections, fileLength, out isZeroFill);
            if (isZeroFill || addressOfNamesOffset < 0 || addressOfNamesOffset >= fileLength)
            {
                result.Status = PeExportParseStatus.MalformedExportTable;
                result.DiagnosticMessage = "AddressOfNames points to invalid or virtual zero-fill offset.";
                return result;
            }

            long addressOfNameOrdinalsOffset = addressOfNameOrdinalsRva != 0
                ? RvaToFileOffset(addressOfNameOrdinalsRva, sections, fileLength, out _)
                : -1;
            long addressOfFunctionsOffset = addressOfFunctionsRva != 0
                ? RvaToFileOffset(addressOfFunctionsRva, sections, fileLength, out _)
                : -1;

            int countToRead = (int)Math.Min(Math.Min(numberOfNames, (uint)maxExportsToRead), MaxExportsToRead);
            var nameRvas = new List<uint>(countToRead);

            fs.Seek(addressOfNamesOffset, SeekOrigin.Begin);
            for (int i = 0; i < countToRead && checked(fs.Position + 4) <= fileLength; i++)
            {
                nameRvas.Add(reader.ReadUInt32());
            }

            // 6. Read Name Strings and Correlate Function Ordinals Safely
            for (int i = 0; i < nameRvas.Count; i++)
            {
                uint nameRva = nameRvas[i];
                long nameOffset = RvaToFileOffset(nameRva, sections, fileLength, out isZeroFill);
                if (!isZeroFill && nameOffset > 0 && nameOffset < fileLength)
                {
                    fs.Seek(nameOffset, SeekOrigin.Begin);
                    var sb = new StringBuilder();
                    int b;
                    while ((b = fs.ReadByte()) > 0 && sb.Length < MaxNameLength && fs.Position <= fileLength)
                    {
                        sb.Append((char)b);
                    }

                    if (sb.Length > 0)
                    {
                        string nameStr = sb.ToString();
                        result.ExportedNames.Add(nameStr);

                        if (!result.HasRecognizedJavaExports && IsRecognizedJavaSymbol(nameStr))
                        {
                            result.HasRecognizedJavaExports = true;
                            result.MatchedJavaSymbol = nameStr;
                        }

                        if (nameStr.Equals("JNI_OnLoad", StringComparison.Ordinal) || nameStr.StartsWith("JNI_OnLoad", StringComparison.Ordinal))
                        {
                            result.HasJniOnLoad = true;
                        }

                        // Inspect Ordinal and Target Function RVA for forwarders and bounds validation
                        if (addressOfNameOrdinalsOffset > 0 && addressOfFunctionsOffset > 0)
                        {
                            long ordinalPos = checked(addressOfNameOrdinalsOffset + (i * 2));
                            if (ordinalPos + 2 <= fileLength)
                            {
                                fs.Seek(ordinalPos, SeekOrigin.Begin);
                                ushort ordinal = reader.ReadUInt16();

                                if (ordinal >= numberOfFunctions)
                                {
                                    result.Status = PeExportParseStatus.MalformedExportTable;
                                    result.DiagnosticMessage = $"Export ordinal index {ordinal} is out of function table bounds (NumberOfFunctions={numberOfFunctions}).";
                                    return result;
                                }

                                long funcPos = checked(addressOfFunctionsOffset + (ordinal * 4));
                                if (funcPos + 4 <= fileLength)
                                {
                                    fs.Seek(funcPos, SeekOrigin.Begin);
                                    uint funcRva = reader.ReadUInt32();

                                    // Detect Forwarder RVA (falls within export directory bounds)
                                    if (funcRva >= exportRva && funcRva < checked(exportRva + exportSize))
                                    {
                                        result.HasForwarders = true;
                                        long forwarderOffset = RvaToFileOffset(funcRva, sections, fileLength, out bool fwdZeroFill);
                                        if (!fwdZeroFill && forwarderOffset > 0 && forwarderOffset < fileLength)
                                        {
                                            fs.Seek(forwarderOffset, SeekOrigin.Begin);
                                            var fwdSb = new StringBuilder();
                                            int fb;
                                            while ((fb = fs.ReadByte()) > 0 && fwdSb.Length < MaxNameLength && fs.Position <= fileLength)
                                            {
                                                fwdSb.Append((char)fb);
                                            }
                                            if (fwdSb.Length > 0)
                                            {
                                                result.Forwarders.Add(fwdSb.ToString());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            result.Status = PeExportParseStatus.Success;
            result.DiagnosticMessage = $"Successfully parsed {result.ExportedNames.Count} exported symbols.";
            return result;
        }
        catch (Exception ex)
        {
            result.Status = PeExportParseStatus.IoError;
            result.DiagnosticMessage = $"PE Parser encountered exception: {ex.Message}";
            return result;
        }
    }

    private static bool IsRecognizedJavaSymbol(string symbolName)
    {
        return symbolName.StartsWith("Java_com_sun_jna_", StringComparison.Ordinal) ||
               symbolName.StartsWith("Java_org_lwjgl_", StringComparison.Ordinal) ||
               symbolName.StartsWith("Java_net_java_games_input_", StringComparison.Ordinal);
    }

    private static long RvaToFileOffset(
        uint rva,
        List<(uint VirtualAddress, uint VirtualSize, uint RawOffset, uint RawSize)> sections,
        long physicalFileLength,
        out bool isVirtualZeroFill)
    {
        isVirtualZeroFill = false;

        foreach (var sec in sections)
        {
            uint span = Math.Max(sec.VirtualSize, sec.RawSize);
            if (rva >= sec.VirtualAddress && rva < checked(sec.VirtualAddress + span))
            {
                uint offsetWithinSec = rva - sec.VirtualAddress;
                // If RVA falls past the raw file-backed size, it is zero-filled virtual memory
                if (offsetWithinSec >= sec.RawSize)
                {
                    isVirtualZeroFill = true;
                    return -1;
                }

                long fileOffset = checked((long)sec.RawOffset + offsetWithinSec);
                if (fileOffset >= physicalFileLength)
                {
                    return -1;
                }

                return fileOffset;
            }
        }

        return -1;
    }
}
