// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using PasswordManagerAccess.Common;
using PemReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;
using PemWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

public enum SshKeyFormat
{
    Original,
    OpenSsh,
    Pkcs8,
    Pkcs1, // Only for RSA keys
}

public class SshKey : VaultItem
{
    public string PrivateKey => KeyAttributes.PrivateKey ?? "";
    public string PublicKey => KeyAttributes.PublicKey ?? "";
    public string Fingerprint => KeyAttributes.Fingerprint ?? "";
    public string KeyType => _keyType ??= FormatKeyType(KeyAttributes.KeyType);

    // TODO: Add encryption support
    public string GetPrivateKey(SshKeyFormat format)
    {
        return format switch
        {
            SshKeyFormat.Original => KeyField.Value ?? "",
            SshKeyFormat.OpenSsh => ConvertToOpenSsh(PrivateKey),
            SshKeyFormat.Pkcs8 => EnsurePkcs8Format(PrivateKey),
            SshKeyFormat.Pkcs1 => KeyAttributes.KeyType?.Type == "rsa" ? ConvertToPkcs1(PrivateKey) : "",
            _ => throw new InternalErrorException("Unknown SSH key format"),
        };
    }

    //
    // Internal
    //

    internal const string SshKeyTemplateId = "114";

    internal SshKey(R.VaultItem itemInfo, Keychain keychain)
        : base(itemInfo, keychain) { }

    internal R.VaultItemSectionField KeyField
    {
        get
        {
            if (_keyField != null)
                return _keyField;

            _keyField = Details.Sections?[0].Fields?[0];

            // It seems the private key is stored in the first section in the first field.
            // Let's verify that to make sure the user doesn't get a lemon.
            if (_keyField is not { Id: "private_key", Kind: "sshKey" })
                throw new InternalErrorException("SSH key field not found");

            return _keyField;
        }
    }

    internal R.SshKeyAttributes KeyAttributes =>
        (_keyAttributes ??= KeyField.Attributes?.SshKey) ?? throw new InternalErrorException("SSH key attributes not found");

    internal static string FormatKeyType(R.SshKeyType? keyType)
    {
        if (keyType == null)
            return "";

        return keyType.Bits == 0 ? keyType.Type : $"{keyType.Type}-{keyType.Bits}";
    }

    internal static string ConvertToOpenSsh(string privateKey)
    {
        var parsed = ParsePkcs8(privateKey);
        var encoded = parsed switch
        {
            // BouncyCastle incorrectly encodes RSA keys as PKCS#1/8, not OpenSSH. So we do it ourselves. Maximum effort.
            RsaPrivateCrtKeyParameters rsa => EncodeRsaToOpenSsh(rsa),

            // Ed25519 keys are encoded OK, so we just send them off to BC
            Ed25519PrivateKeyParameters ed25519 => OpenSshPrivateKeyUtilities.EncodePrivateKey(ed25519),

            // 1Password supports only RSA and Ed25519 keys, so we do too.
            _ => throw new InternalErrorException($"Expected an RSA and an Ed25519 key, got: {parsed.GetType().Name}"),
        };

        return FormatPemKey("OPENSSH PRIVATE KEY", encoded);
    }

    internal static string EnsurePkcs8Format(string privateKey)
    {
        if (privateKey.StartsWith("-----BEGIN PRIVATE KEY-----"))
            return privateKey;

        var marker = privateKey.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        throw new InternalErrorException($"Expected a private key in PKCS#8 format, got '{marker}'");
    }

    internal static string ConvertToPkcs1(string privateKey)
    {
        var parsed = ParsePkcs8(privateKey);
        if (parsed is not RsaPrivateCrtKeyParameters rsa)
            throw new InternalErrorException("Only RSA keys are supported in PKCS#1 format");

        return FormatPemKey(new MiscPemGenerator(rsa));
    }

    internal static AsymmetricKeyParameter ParsePkcs8(string privateKey)
    {
        EnsurePkcs8Format(privateKey);

        using var pemReader = new PemReader(new StringReader(privateKey));
        return PrivateKeyFactory.CreateKey(pemReader.ReadPemObject().Content);
    }

    internal static string FormatPemKey(string marker, byte[] privateKey)
    {
        return FormatPemKey(new PemObject(marker, privateKey));
    }

    internal static string FormatPemKey(PemObjectGenerator pemObject)
    {
        using var textWriter = new StringWriter();
        using var pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(pemObject);
        return textWriter.ToString();
    }

    internal static byte[] EncodeRsaToOpenSsh(RsaPrivateCrtKeyParameters rsa)
    {
        const string keyType = "ssh-rsa";
        const int blockSize = 8;

        // encode public and private parts together
        using var memoryStream = new MemoryStream();
        using var writer = new BinaryWriter(memoryStream);

        var publicKeyBytes = new OutputSpanStream(new byte[64 * 1024]); // TODO: Figure out a better size
        publicKeyBytes.PutSshStr(keyType);
        publicKeyBytes.PutBigInt(rsa.PublicExponent);
        publicKeyBytes.PutBigInt(rsa.Modulus);

        var privateKeyBytes = new OutputSpanStream(new byte[64 * 1024]); // TODO: Figure out a better size
        var randomMarker = Crypto.RandomBytes(4);
        privateKeyBytes.WriteBytes(randomMarker); // Twice, not a typo
        privateKeyBytes.WriteBytes(randomMarker); // Twice, not a typo
        privateKeyBytes.PutSshStr(keyType);
        privateKeyBytes.PutBigInt(rsa.Modulus);
        privateKeyBytes.PutBigInt(rsa.PublicExponent);
        privateKeyBytes.PutBigInt(rsa.Exponent);
        privateKeyBytes.PutBigInt(rsa.QInv);
        privateKeyBytes.PutBigInt(rsa.P);
        privateKeyBytes.PutBigInt(rsa.Q);
        privateKeyBytes.PutSshStr(""); // Comment

        for (byte pad = 1; privateKeyBytes.Position % blockSize != 0; pad++)
            privateKeyBytes.WriteByte(pad);

        var topLevel = new OutputSpanStream(new byte[64 * 1024]); // TODO: Figure out a better size

        // top-level structure
        topLevel.WriteBytes("openssh-key-v1\0".ToBytes());
        topLevel.PutSshStr("none"); // Cipher name
        topLevel.PutSshStr("none"); // KDF name
        topLevel.PutSshStr([]);
        topLevel.WriteUInt32BigEndian(1); // Number of keys
        topLevel.PutSshStr(publicKeyBytes.Span[..publicKeyBytes.Position].ToArray()); // TODO: Don't copy
        topLevel.PutSshStr(privateKeyBytes.Span[..privateKeyBytes.Position].ToArray()); // TODO: Don't copy

        return topLevel.Span[..topLevel.Position].ToArray(); // TODO: Don't copy
    }

    //
    // Private
    //

    private R.VaultItemSectionField? _keyField;
    private R.SshKeyAttributes? _keyAttributes;
    private string? _keyType;
}

file static class SshKeyExtensions
{
    internal static void PutSshStr(this ref OutputSpanStream stream, string s)
    {
        stream.PutSshStr(s.ToBytes());
    }

    internal static void PutSshStr(this ref OutputSpanStream stream, byte[] bytes)
    {
        stream.WriteUInt32BigEndian((uint)bytes.Length);
        stream.WriteBytes(bytes);
    }

    internal static void PutBigInt(this ref OutputSpanStream stream, BigInteger i)
    {
        stream.PutSshStr(i.ToByteArray());
    }
}
