using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TryZ.Data;

/// <summary>
/// Encrypts small secrets (session cookies, bearer/authorization tokens, passwords, API keys) at rest using the Windows
/// Data Protection API (DPAPI, <c>CryptProtectData</c>) bound to the current Windows user. The ciphertext is stored as
/// <c>enc:v1:</c> + Base64 and can only be decrypted by the same user on the same machine, so the plaintext never
/// touches the settings file on disk. A per-application entropy value binds the ciphertext to TryZ.
/// </summary>
internal static class Secret
{
    private const string Prefix = "enc:v1:";
    private const int CryptProtectUiForbidden = 0x1;
    // Secondary entropy so a blob cannot be decrypted by another DPAPI-using app running as the same user.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("TryZ.Security.Suite/settings/v1");

    /// <summary>True when a stored value is a DPAPI ciphertext produced by <see cref="Protect"/>.</summary>
    public static bool IsProtected(string? stored) => stored != null && stored.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>Encrypts a secret for storage. Empty input stays empty. On any failure the plaintext is returned unchanged
    /// (encryption is best-effort; the setting must still work on platforms where DPAPI is unavailable).</summary>
    public static string Protect(string? plaintext)
    {
        if (string.IsNullOrEmpty(plaintext)) return string.Empty;
        if (IsProtected(plaintext)) return plaintext; // already encrypted; do not double-wrap
        if (!OperatingSystem.IsWindows()) return plaintext;
        try
        {
            byte[] cipher = Transform(Encoding.UTF8.GetBytes(plaintext), protect: true);
            return Prefix + Convert.ToBase64String(cipher);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or InvalidOperationException)
        {
            return plaintext;
        }
    }

    /// <summary>Decrypts a stored secret. Legacy plaintext (no prefix) is returned unchanged so existing settings keep
    /// working; a ciphertext that cannot be decrypted (copied to another user/machine) yields an empty string.</summary>
    public static string Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return string.Empty;
        if (!IsProtected(stored)) return stored; // legacy plaintext, migrated to ciphertext on the next Save()
        if (!OperatingSystem.IsWindows()) return string.Empty;
        try
        {
            byte[] cipher = Convert.FromBase64String(stored[Prefix.Length..]);
            return Encoding.UTF8.GetString(Transform(cipher, protect: false));
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or DllNotFoundException or EntryPointNotFoundException)
        {
            return string.Empty;
        }
    }

    private static byte[] Transform(byte[] input, bool protect)
    {
        var inBlob = default(DataBlob);
        var entropyBlob = default(DataBlob);
        var outBlob = default(DataBlob);
        var inHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        try
        {
            inBlob = new DataBlob { cbData = input.Length, pbData = inHandle.AddrOfPinnedObject() };
            entropyBlob = new DataBlob { cbData = Entropy.Length, pbData = entropyHandle.AddrOfPinnedObject() };
            bool ok = protect
                ? CryptProtectData(ref inBlob, "TryZ", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, ref outBlob)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, ref outBlob);
            if (!ok) throw new InvalidOperationException($"DPAPI {(protect ? "protect" : "unprotect")} failed (0x{Marshal.GetLastWin32Error():X8})");
            byte[] result = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
            return result;
        }
        finally
        {
            if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
            inHandle.Free();
            entropyHandle.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob pDataIn, string? szDataDescr, ref DataBlob pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DataBlob pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(ref DataBlob pDataIn, IntPtr ppszDataDescr, ref DataBlob pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DataBlob pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
}

/// <summary>Serializes a string property as a DPAPI ciphertext and decrypts it back on read. Applied to secret fields so
/// credentials are never written to settings.json in cleartext. Reading tolerates legacy plaintext values.</summary>
internal sealed class EncryptedStringConverter : JsonConverter<string>
{
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        Secret.Unprotect(reader.TokenType == JsonTokenType.Null ? null : reader.GetString());

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) =>
        writer.WriteStringValue(Secret.Protect(value));
}

/// <summary>Encrypts each entry of a string list at rest (e.g. extra request headers that may carry API keys).</summary>
internal sealed class EncryptedStringListConverter : JsonConverter<List<string>>
{
    public override List<string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var list = new List<string>();
        if (reader.TokenType == JsonTokenType.Null) return list;
        if (reader.TokenType != JsonTokenType.StartArray) throw new JsonException("expected an array of secrets");
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            string plain = Secret.Unprotect(reader.TokenType == JsonTokenType.Null ? null : reader.GetString());
            if (plain.Length > 0) list.Add(plain);
        }
        return list;
    }

    public override void Write(Utf8JsonWriter writer, List<string> value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        foreach (var item in value) writer.WriteStringValue(Secret.Protect(item));
        writer.WriteEndArray();
    }
}
