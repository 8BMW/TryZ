using System.Security.Cryptography;
using System.Text;

namespace TryZ.Data;

/// <summary>
/// Encrypts small secrets for the current Windows user (DPAPI). Another account, or a copy of settings.json on
/// another machine, can't read them back; it simply finds the entry empty and asks for it again.
/// </summary>
internal static class SecretStore
{
    // Ties the blobs to this application so another DPAPI consumer can't be tricked into decrypting them.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("TryZ.AuthHeader.v1");

    public static string Protect(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        byte[] plain = Encoding.UTF8.GetBytes(value);
        try { return Convert.ToBase64String(ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser)); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    /// <summary>The secret, or null when it was written by another user or machine, or is damaged.</summary>
    public static string? Unprotect(string blob)
    {
        if (string.IsNullOrEmpty(blob)) return null;
        try
        {
            byte[] plain = ProtectedData.Unprotect(Convert.FromBase64String(blob), Entropy, DataProtectionScope.CurrentUser);
            try { return Encoding.UTF8.GetString(plain); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
