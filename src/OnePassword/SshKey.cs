// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

public class SshKey : VaultItem
{
    public string Key => KeyField.Value ?? "";
    public string PrivateKey => KeyAttributes.PrivateKey ?? "";
    public string PublicKey => KeyAttributes.PublicKey ?? "";
    public string Fingerprint => KeyAttributes.Fingerprint ?? "";
    public string KeyType => _keyType ??= FormatKeyType(KeyAttributes.KeyType);

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

    //
    // Private
    //

    private R.VaultItemSectionField? _keyField;
    private R.SshKeyAttributes? _keyAttributes;
    private string? _keyType;
}
