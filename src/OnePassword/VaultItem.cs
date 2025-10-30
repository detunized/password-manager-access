// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Collections.Generic;

namespace PasswordManagerAccess.OnePassword;

public class VaultItem
{
    public readonly record struct Field(string Name, string Value, string Section);

    public string Id => _itemInfo.Id ?? "";

    public string Name => Overview.Title ?? "";
    public string Description => Overview.AdditionalInfo ?? "";
    public string Note => Details.Note ?? "";

    public Field[] Fields => _fields ??= ParseFields();

    //
    // Internal
    //

    internal string TemplateId => _itemInfo.TemplateId ?? "";
    internal Model.VaultItemOverview Overview => _overview ??= DecryptOverview();
    internal Model.VaultItemDetails Details => _details ??= DecryptDetails();

    internal VaultItem(Model.VaultItem itemInfo, Keychain keychain)
    {
        _itemInfo = itemInfo;
        _keychain = keychain;
    }

    internal Model.Encrypted EncryptedOverview => _itemInfo.Overview;
    internal Model.Encrypted EncryptedDetails => _itemInfo.Details;

    internal Model.VaultItemOverview DecryptOverview() => Util.Decrypt<Model.VaultItemOverview>(_itemInfo.Overview, _keychain);

    internal Model.VaultItemDetails DecryptDetails() => Util.Decrypt<Model.VaultItemDetails>(_itemInfo.Details, _keychain);

    internal Field[] ParseFields()
    {
        var fields = new List<Field>();

        foreach (var section in Details.Sections ?? [])
        foreach (var field in section.Fields ?? [])
            fields.Add(new Field(field.Name ?? "", field.Value ?? "", section.Name ?? ""));

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

    private readonly Model.VaultItem _itemInfo;
    private readonly Keychain _keychain;
    private Model.VaultItemOverview? _overview;
    private Model.VaultItemDetails? _details;
    private Field[]? _fields;
}
