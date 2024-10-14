// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

// TODO: Move to a separate file
public class VaultItem
{
    public string Id => _itemInfo.Id ?? "";

    public string Name => Overview.Title ?? "";
    public string Description => Overview.AdditionalInfo ?? "";

    //
    // Internal
    //

    internal R.VaultItemOverview Overview => _overview ??= DecryptOverview();
    internal R.VaultItemDetails Details => _details ??= DecryptDetails();

    internal VaultItem(R.VaultItem itemInfo, Keychain keychain)
    {
        _itemInfo = itemInfo;
        _keychain = keychain;
    }

    internal R.VaultItemOverview DecryptOverview() => Util.Decrypt<R.VaultItemOverview>(_itemInfo.Overview, _keychain);

    internal R.VaultItemDetails DecryptDetails() => Util.Decrypt<R.VaultItemDetails>(_itemInfo.Details, _keychain);

    //
    // Private
    //

    private readonly R.VaultItem _itemInfo;
    private readonly Keychain _keychain;
    private R.VaultItemOverview? _overview;
    private R.VaultItemDetails? _details;
}

public class SshKey : VaultItem
{
    public string Note => Details.Note ?? "";
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

    internal R.VaultItemSectionField KeyField =>
        (_keyField ??= Details.Sections?[0].Fields?[0]) ?? throw new InternalErrorException("SSH key field not found");

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
