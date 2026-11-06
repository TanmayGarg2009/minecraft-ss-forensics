using System;
using System.IO;
using System.Text;
using MinecraftSsForensics.Scanner.Process;
using Xunit;

namespace MinecraftSsForensics.Scanner.Tests;

public class PeExportParserHardeningTests : IDisposable
{
    private readonly string _tempDir;

    public PeExportParserHardeningTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "PeHardeningTests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, true);
        }
        catch { }
    }

    [Fact]
    public void ParseExports_FileNotFound_ReturnsFileNotFoundStatus()
    {
        string nonExistent = Path.Combine(_tempDir, "non_existent.dll");
        var result = PeExportParser.ParseExports(nonExistent);

        Assert.Equal(PeExportParseStatus.FileNotFound, result.Status);
        Assert.False(result.HasRecognizedJavaExports);
    }

    [Fact]
    public void ParseExports_FileTooSmall_ReturnsFileTooSmallStatus()
    {
        string truncated = Path.Combine(_tempDir, "truncated.dll");
        File.WriteAllBytes(truncated, new byte[] { 0x4D, 0x5A, 0x00 }); // Only 3 bytes

        var result = PeExportParser.ParseExports(truncated);
        Assert.Equal(PeExportParseStatus.FileTooSmall, result.Status);
    }

    [Fact]
    public void ParseExports_InvalidDosHeader_ReturnsInvalidDosHeader()
    {
        string invalidDos = Path.Combine(_tempDir, "invalid_dos.dll");
        byte[] bytes = new byte[128];
        bytes[0] = 0x7F; // ELF header or random byte instead of MZ
        bytes[1] = 0x45;
        File.WriteAllBytes(invalidDos, bytes);

        var result = PeExportParser.ParseExports(invalidDos);
        Assert.Equal(PeExportParseStatus.InvalidDosHeader, result.Status);
    }

    [Fact]
    public void ParseExports_InvalidPeOffset_ReturnsInvalidPeOffset()
    {
        string invalidOffset = Path.Combine(_tempDir, "invalid_offset.dll");
        byte[] bytes = new byte[128];
        bytes[0] = 0x4D; bytes[1] = 0x5A; // "MZ"
        // Set e_lfanew to 0x100000 (past file size)
        BitConverter.GetBytes(0x100000).CopyTo(bytes, 0x3C);
        File.WriteAllBytes(invalidOffset, bytes);

        var result = PeExportParser.ParseExports(invalidOffset);
        Assert.Equal(PeExportParseStatus.InvalidPeOffset, result.Status);
    }

    [Fact]
    public void ParseExports_InvalidPeSignature_ReturnsInvalidPeSignature()
    {
        string badSig = Path.Combine(_tempDir, "bad_sig.dll");
        byte[] bytes = new byte[256];
        bytes[0] = 0x4D; bytes[1] = 0x5A; // "MZ"
        BitConverter.GetBytes(0x40).CopyTo(bytes, 0x3C); // e_lfanew = 0x40
        bytes[0x40] = 0x58; bytes[0x41] = 0x58; // "XX" instead of "PE\0\0"
        File.WriteAllBytes(badSig, bytes);

        var result = PeExportParser.ParseExports(badSig);
        Assert.Equal(PeExportParseStatus.InvalidPeSignature, result.Status);
    }

    [Fact]
    public void ParseExports_ValidPeWithRecognizedJnaSymbol_DetectsJavaSymbol()
    {
        string peFile = Path.Combine(_tempDir, "valid_jna.dll");
        byte[] peBytes = CreateSyntheticPeWithExport(
            exportRva: 0x1000,
            symbolName: "Java_com_sun_jna_Native_initIDs");
        File.WriteAllBytes(peFile, peBytes);

        var result = PeExportParser.ParseExports(peFile);
        Assert.Equal(PeExportParseStatus.Success, result.Status);
        Assert.True(result.HasRecognizedJavaExports);
        Assert.Equal("Java_com_sun_jna_Native_initIDs", result.MatchedJavaSymbol);
        Assert.Contains("Java_com_sun_jna_Native_initIDs", result.ExportedNames);

        bool quickCheck = PeExportParser.HasRecognizedJavaExports(peFile, out string matched);
        Assert.True(quickCheck);
        Assert.Equal("Java_com_sun_jna_Native_initIDs", matched);
    }

    [Fact]
    public void ParseExports_ValidPeWithUnrelatedSymbol_ReturnsSuccessWithoutJavaMatch()
    {
        string peFile = Path.Combine(_tempDir, "normal_native.dll");
        byte[] peBytes = CreateSyntheticPeWithExport(
            exportRva: 0x1000,
            symbolName: "CustomNativeFunction");
        File.WriteAllBytes(peFile, peBytes);

        var result = PeExportParser.ParseExports(peFile);
        Assert.Equal(PeExportParseStatus.Success, result.Status);
        Assert.False(result.HasRecognizedJavaExports);
        Assert.Contains("CustomNativeFunction", result.ExportedNames);
    }

    [Fact]
    public void ParseExports_VirtualZeroFillRegion_IdentifiedAsZeroFill()
    {
        string peFile = Path.Combine(_tempDir, "zerofill.dll");
        // Create PE where section VirtualSize is 0x2000, but RawSize is only 0x200
        // and export RVA points to 0x1800 (in the virtual-only unbacked area)
        byte[] peBytes = CreateSyntheticPeWithExport(
            exportRva: 0x1800,
            symbolName: "GhostExport",
            rawSectionSize: 0x200,
            virtualSectionSize: 0x2000);
        File.WriteAllBytes(peFile, peBytes);

        var result = PeExportParser.ParseExports(peFile);
        Assert.Equal(PeExportParseStatus.VirtualZeroFillRegion, result.Status);
        Assert.False(result.HasRecognizedJavaExports);
    }

    [Fact]
    public void ParseExports_ArchitectureMismatch_ReturnsUnsupportedArchitecture()
    {
        string peFile = Path.Combine(_tempDir, "arch_mismatch.dll");
        byte[] peBytes = CreateSyntheticPeWithExport(0x1000, "Func");
        // Change optional header magic at e_lfanew (0x40) + 24 = 0x58 from 0x20B (PE32+) to 0x10B (PE32) while machine is 0x8664
        peBytes[0x58] = 0x0B;
        peBytes[0x59] = 0x01;
        File.WriteAllBytes(peFile, peBytes);

        var result = PeExportParser.ParseExports(peFile);
        Assert.Equal(PeExportParseStatus.UnsupportedArchitecture, result.Status);
        Assert.Contains("Architecture mismatch", result.DiagnosticMessage);
    }

    [Fact]
    public void ParseExports_OrdinalOutOfBounds_ReturnsMalformedExportTable()
    {
        string peFile = Path.Combine(_tempDir, "bad_ordinal.dll");
        byte[] peBytes = CreateSyntheticPeWithExport(0x1000, "BadOrdinalFunc");
        // Ordinal is at exportOffsetInFile + 48 = 0x200 + 48 = 0x230
        BitConverter.GetBytes((ushort)999).CopyTo(peBytes, 0x200 + 48);
        File.WriteAllBytes(peFile, peBytes);

        var result = PeExportParser.ParseExports(peFile);
        Assert.Equal(PeExportParseStatus.MalformedExportTable, result.Status);
        Assert.Contains("out of function table bounds", result.DiagnosticMessage);
    }

    [Fact]
    public void CheckJavaNativeProvenance_UnsignedTempDllWithJniOnLoad_IsIdentifiedAsInjectionArtifactNotLegitimate()
    {
        string peFile = Path.Combine(_tempDir, "cheat_injector.dll");
        byte[] peBytes = CreateSyntheticPeWithExport(0x1000, "JNI_OnLoad");
        File.WriteAllBytes(peFile, peBytes);

        var (isLegit, explanation) = ProcessScanner.CheckJavaNativeProvenance(peFile, "cheat_injector.dll");
        Assert.False(isLegit);
        Assert.Contains("JNI_OnLoad", explanation);
        Assert.Contains("potential injection artifact", explanation);
    }

    // Helper to synthesize a valid 64-bit PE file with an Export Directory
    private static byte[] CreateSyntheticPeWithExport(
        uint exportRva,
        string symbolName,
        uint rawSectionSize = 0x1000,
        uint virtualSectionSize = 0x1000)
    {
        int totalSize = 0x200 + (int)rawSectionSize;
        byte[] buffer = new byte[totalSize];

        using var ms = new MemoryStream(buffer);
        using var writer = new BinaryWriter(ms, Encoding.ASCII);

        // 1. DOS Header
        writer.Write((ushort)0x5A4D); // "MZ"
        ms.Seek(0x3C, SeekOrigin.Begin);
        writer.Write(0x40); // e_lfanew = 0x40

        // 2. PE Header at 0x40
        ms.Seek(0x40, SeekOrigin.Begin);
        writer.Write((uint)0x00004550); // "PE\0\0"
        writer.Write((ushort)0x8664);   // Machine AMD64
        writer.Write((ushort)1);        // NumberOfSections = 1
        writer.Write((uint)0);          // TimeDateStamp
        writer.Write((uint)0);          // PointerToSymbolTable
        writer.Write((uint)0);          // NumberOfSymbols
        writer.Write((ushort)240);      // SizeOfOptionalHeader = 240
        writer.Write((ushort)0x2002);   // Characteristics (DLL)

        // 3. Optional Header (64-bit PE+)
        long optHeaderPos = ms.Position;
        writer.Write((ushort)0x20B);     // Magic PE32+
        writer.Write((byte)1); writer.Write((byte)0); // Linker version
        writer.Write((uint)0);          // SizeOfCode
        writer.Write((uint)0);          // SizeOfInitializedData
        writer.Write((uint)0);          // SizeOfUninitializedData
        writer.Write((uint)0x1000);     // AddressOfEntryPoint
        writer.Write((uint)0x1000);     // BaseOfCode
        writer.Write((ulong)0x180000000); // ImageBase
        writer.Write((uint)0x1000);     // SectionAlignment
        writer.Write((uint)0x200);      // FileAlignment
        ms.Seek(optHeaderPos + 112, SeekOrigin.Begin); // DataDirectory[0] (Export Table)
        writer.Write(exportRva);        // Export RVA
        writer.Write((uint)0x200);      // Export Size

        // 4. Section Header at optHeaderPos + 240
        ms.Seek(optHeaderPos + 240, SeekOrigin.Begin);
        writer.Write(Encoding.ASCII.GetBytes(".edata\0\0"));
        writer.Write(virtualSectionSize); // VirtualSize
        writer.Write((uint)0x1000);       // VirtualAddress (RVA)
        writer.Write(rawSectionSize);     // SizeOfRawData
        writer.Write((uint)0x200);        // PointerToRawData
        writer.Write((uint)0);            // PointerToRelocations
        writer.Write((uint)0);            // PointerToLinenumbers
        writer.Write((ushort)0);          // NumberOfRelocations
        writer.Write((ushort)0);          // NumberOfLinenumbers
        writer.Write((uint)0x40000040);   // Characteristics (INITIALIZED_DATA | READ)

        // 5. Populate Export Table inside section at raw offset 0x200 if file-backed
        if (exportRva >= 0x1000 && exportRva < 0x1000 + rawSectionSize)
        {
            long exportOffsetInFile = 0x200 + (exportRva - 0x1000);
            ms.Seek(exportOffsetInFile, SeekOrigin.Begin);

            // Export Directory Table (40 bytes)
            writer.Write((uint)0); // Characteristics (offset 0)
            writer.Write((uint)0); // TimeDateStamp (offset 4)
            writer.Write((ushort)0); writer.Write((ushort)0); // Major/Minor (offset 8)
            writer.Write((uint)0x1028); // Name RVA (offset 12)
            writer.Write((uint)1); // Base (offset 16)
            writer.Write((uint)1); // NumberOfFunctions = 1 (offset 20)
            writer.Write((uint)1); // NumberOfNames = 1 (offset 24)
            writer.Write((uint)(exportRva + 40)); // AddressOfFunctions (offset 28)
            writer.Write((uint)(exportRva + 44)); // AddressOfNames (offset 32)
            writer.Write((uint)(exportRva + 48)); // AddressOfNameOrdinals (offset 36)

            // Functions array (1 entry = RVA 0x1000) at offset 40
            writer.Write((uint)0x1000);

            // Names array (1 entry = RVA pointing to string at exportRva + 50) at offset 44
            uint stringRva = exportRva + 50;
            writer.Write(stringRva);

            // Ordinals array (1 entry = 0) at offset 48
            writer.Write((ushort)0);

            // Write symbol string at offset 50
            writer.Write(Encoding.ASCII.GetBytes(symbolName));
            writer.Write((byte)0); // Null terminator
        }

        return buffer;
    }
}
