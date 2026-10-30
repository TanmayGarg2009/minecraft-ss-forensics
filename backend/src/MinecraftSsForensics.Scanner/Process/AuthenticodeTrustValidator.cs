using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace MinecraftSsForensics.Scanner.Process;

public enum AuthenticodeTrustStatus
{
    Trusted,
    Unsigned,
    TamperedBadDigest,
    UntrustedRootOrSelfSigned,
    Expired,
    Revoked,
    RevocationOffline,
    VerificationFailed
}

public class AuthenticodeVerificationResult
{
    public bool IsSigned { get; set; }
    public bool IsTrusted { get; set; }
    public AuthenticodeTrustStatus TrustStatus { get; set; } = AuthenticodeTrustStatus.Unsigned;
    public string StatusExplanation { get; set; } = string.Empty;
    public string? SignerSubject { get; set; }
    public string? SignerIssuer { get; set; }
    public string? CertificateThumbprint { get; set; }
    public DateTime? ValidFrom { get; set; }
    public DateTime? ValidTo { get; set; }
    public uint RawHResult { get; set; }
}

/// <summary>
/// Verifies Authenticode digital signatures on Windows executables, modules (.dll), and kernel drivers (.sys).
/// Uses WinVerifyTrust to validate cryptographic hash matches, chain trust, and root authority validity.
/// Replaces superficial certificate presence checks with genuine Windows trust verification.
/// </summary>
public static class AuthenticodeTrustValidator
{
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_SAFER_FLAG = 0x00000100;

    // Standard WinVerifyTrust HRESULT return codes
    private const uint ERROR_SUCCESS = 0x00000000;
    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_BAD_DIGEST = 0x80096010;
    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
    private const uint CERT_E_EXPIRED = 0x800B0101;
    private const uint CERT_E_REVOKED = 0x800B010E;
    private const uint CRYPT_E_REVOCATION_OFFLINE = 0x80092013;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    /// <summary>
    /// Audits the Authenticode signature and trust chain of the specified executable or driver file.
    /// </summary>
    public static AuthenticodeVerificationResult VerifyFileTrust(string filePath)
    {
        var result = new AuthenticodeVerificationResult();

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            result.StatusExplanation = "File does not exist or path is empty.";
            return result;
        }

        if (!OperatingSystem.IsWindows())
        {
            // Non-Windows fallback: attempt certificate extraction only
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                result.IsSigned = true;
                result.SignerSubject = cert.Subject;
                result.SignerIssuer = cert.Issuer;
                result.TrustStatus = AuthenticodeTrustStatus.VerificationFailed;
                result.StatusExplanation = "Authenticode certificate present, but WinVerifyTrust requires Windows OS.";
            }
            catch
            {
                result.IsSigned = false;
                result.TrustStatus = AuthenticodeTrustStatus.Unsigned;
                result.StatusExplanation = "No Authenticode signature found.";
            }
            return result;
        }

        // 1. Perform native WinVerifyTrust validation first
        IntPtr pFilePath = Marshal.StringToHGlobalUni(filePath);
        IntPtr pWvtData = IntPtr.Zero;
        IntPtr pFileInfo = IntPtr.Zero;

        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pFilePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            var wvtData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE, // Do not fail offline scans if network revocation CRL is unreachable
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_IGNORE,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            pWvtData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(wvtData, pWvtData, false);

            uint hresult = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pWvtData);
            result.RawHResult = hresult;

            switch (hresult)
            {
                case ERROR_SUCCESS:
                    result.IsSigned = true;
                    result.IsTrusted = true;
                    result.TrustStatus = AuthenticodeTrustStatus.Trusted;
                    result.StatusExplanation = "Authenticode signature is valid, digest matches, and certificate chain terminates in a trusted root.";
                    break;

                case TRUST_E_NOSIGNATURE:
                    result.IsSigned = false;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.Unsigned;
                    result.StatusExplanation = "The file is not signed or does not have a recognizable signature.";
                    break;

                case TRUST_E_BAD_DIGEST:
                    result.IsSigned = true;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.TamperedBadDigest;
                    result.StatusExplanation = "TAMPERED / CORRUPT: The file hash does not match the signature hash! File was modified after signing.";
                    break;

                case CERT_E_UNTRUSTEDROOT:
                    result.IsSigned = true;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.UntrustedRootOrSelfSigned;
                    result.StatusExplanation = "UNTRUSTED SIGNER: Certificate chain terminates in an untrusted root certificate (e.g. self-signed or test certificate).";
                    break;

                case CERT_E_EXPIRED:
                    result.IsSigned = true;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.Expired;
                    result.StatusExplanation = "EXPIRED: A required certificate in the chain is outside its validity period.";
                    break;

                case CERT_E_REVOKED:
                    result.IsSigned = true;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.Revoked;
                    result.StatusExplanation = "REVOKED: The certificate has been explicitly revoked by its issuing authority.";
                    break;

                case CRYPT_E_REVOCATION_OFFLINE:
                    result.IsSigned = true;
                    result.IsTrusted = true;
                    result.TrustStatus = AuthenticodeTrustStatus.RevocationOffline;
                    result.StatusExplanation = "Signature is valid and chain is trusted; network revocation check was offline/skipped.";
                    break;

                case TRUST_E_EXPLICIT_DISTRUST:
                    result.IsSigned = true;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.UntrustedRootOrSelfSigned;
                    result.StatusExplanation = "DISTRUSTED: The certificate was explicitly marked as untrusted on this system.";
                    break;

                default:
                    result.IsSigned = true;
                    result.IsTrusted = false;
                    result.TrustStatus = AuthenticodeTrustStatus.VerificationFailed;
                    result.StatusExplanation = $"WinVerifyTrust verification returned error code 0x{hresult:X8}.";
                    break;
            }
        }
        catch (Exception ex)
        {
            result.IsTrusted = false;
            result.TrustStatus = AuthenticodeTrustStatus.VerificationFailed;
            result.StatusExplanation = $"Verification exception: {ex.Message}";
        }
        finally
        {
            if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
            if (pWvtData != IntPtr.Zero) Marshal.FreeHGlobal(pWvtData);
            if (pFilePath != IntPtr.Zero) Marshal.FreeHGlobal(pFilePath);
        }

        // 2. Safely attempt to extract embedded certificate metadata
        if (result.IsSigned)
        {
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                result.SignerSubject = cert.Subject;
                result.SignerIssuer = cert.Issuer;
                result.CertificateThumbprint = cert.Thumbprint;
                result.ValidFrom = cert.NotBefore;
                result.ValidTo = cert.NotAfter;
            }
            catch
            {
                // Catalog signed or complex envelope: WinVerifyTrust already validated authenticity
                if (result.IsTrusted && string.IsNullOrEmpty(result.SignerSubject))
                {
                    result.SignerSubject = "Verified Windows Authenticode Signer";
                }
            }
        }

        return result;
    }
}
