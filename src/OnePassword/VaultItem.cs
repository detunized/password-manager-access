// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Collections.Generic;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

public class VaultItem
{
    public readonly record struct Field(string Name, string Value, string Section);

    public string Id => _itemInfo.Id ?? "";

    public string Name => Overview.Title ?? "";
    public string Description => Overview.AdditionalInfo ?? "";
    public string Note => Details.Note ?? "";
    public string CreatedAt => _itemInfo.CreatedAt ?? "";
    public string UpdatedAt => _itemInfo.UpdatedAt ?? "";

    public Field[] Fields => _fields ??= ParseFields();

    //
    // Internal
    //

    internal string TemplateId => _itemInfo.TemplateId ?? "";
    internal R.VaultItemOverview Overview => _overview ??= DecryptOverview();
    internal R.VaultItemDetails Details => _details ??= DecryptDetails();

    internal VaultItem(R.VaultItem itemInfo, Keychain keychain)
    {
        _itemInfo = itemInfo;
        _keychain = keychain;
    }

    internal R.Encrypted EncryptedOverview => _itemInfo.Overview;
    internal R.Encrypted EncryptedDetails => _itemInfo.Details;

    internal R.VaultItemOverview DecryptOverview() => Util.Decrypt<R.VaultItemOverview>(_itemInfo.Overview, _keychain);

    internal R.VaultItemDetails DecryptDetails() => Util.Decrypt<R.VaultItemDetails>(_itemInfo.Details, _keychain);

    internal Field[] ParseFields()
    {
        var fields = new List<Field>();

        foreach (var section in Details.Sections ?? [])
        foreach (var field in section.Fields ?? [])
            fields.Add(new Field(field.Name, field.Value, section.Name));

        return fields.ToArray();
    }

    internal string FindField(string name)
    {
        // Logins have their fields here.
        if (Details.Fields != null)
            foreach (var field in Details.Fields)
                if (field.Designation == name)
                    return field.Value ?? "";

        // Servers have some of the stuff stored here.
        // There wasn't nearly enough nesting above. Gimme more!
        if (Details.Sections != null)
            foreach (var section in Details.Sections)
                if (section.Fields != null)
                    foreach (var field in section.Fields)
                        if (field.Name == name)
                            return field.Value ?? "";

        return "";
    }

    //
    // Private
    //

    private readonly R.VaultItem _itemInfo;
    private readonly Keychain _keychain;
    private R.VaultItemOverview? _overview;
    private R.VaultItemDetails? _details;
    private Field[]? _fields;
}
