// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

/// The vault key and the attributes are decrypted on demand and cached for quick access later on.
/// The VaultInfo doesn't contain the entries. To retrieve the entries/accounts call Client.OpenVault.
public class VaultInfo
{
    public string Id { get; }

    // Decrypted on demand
    public string Name => Attributes.Name ?? "";
    public string Description => Attributes.Description ?? "";

    //
    // Non public
    //

    internal VaultInfo(string id, Encrypted encryptedAttributes, Encrypted encryptedKey, Keychain keychain)
    {
        Id = id;
        _encryptedAttributes = encryptedAttributes;
        _encryptedKey = encryptedKey;
        _keychain = keychain;
    }

    // Mutates the keychain
    internal R.VaultAttributes Decrypt()
    {
        DecryptKeyIntoKeychain();
        return Util.Decrypt<R.VaultAttributes>(_encryptedAttributes, _keychain);
    }

    // Mutates the keychain
    internal void DecryptKeyIntoKeychain()
    {
        // The key is added to the keychain as it later used to decrypt the account details as well
        if (!_keychain.CanDecrypt(_encryptedAttributes))
            Util.DecryptAesKey(_encryptedKey, _keychain);
    }

    private readonly Encrypted _encryptedAttributes;
    private readonly Encrypted _encryptedKey;
    private readonly Keychain _keychain;

    // Cache
    private R.VaultAttributes Attributes => _attributes ??= Decrypt();
    private R.VaultAttributes? _attributes;
}
