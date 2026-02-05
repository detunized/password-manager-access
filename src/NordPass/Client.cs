// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Text.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.NordPass;

internal static class Client
{
    public const string ApiBase = "https://api.nordpass.com";

    internal static readonly Dictionary<string, string> DefaultHeaders = new() { ["nordpass-user-agent"] = "NordPass webvault (7.3.14) webvault" };

    internal static (string Verifier, string Challenge) GeneratePkce()
    {
        var verifier = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var challenge = Common.Crypto.Sha256(verifier.ToBytes()).ToHex();
        return (verifier, challenge);
    }

    internal static RestClient MakeRestClient(IRestTransport transport) =>
        new RestClient(transport, ApiBase, defaultHeaders: DefaultHeaders, useSystemJson: true);

    internal static BaseException MakeError<T>(RestResponse<T> response)
    {
        if (response.HasError)
            return new NetworkErrorException("Network error", response.Error);

        return new InternalErrorException($"Request failed with HTTP {(int)response.StatusCode}");
    }

    //
    // Decryption
    //

    // Decrypts a vault item through the full chain: item key → value key → value → Account.
    // The identity X25519 keys must be pre-derived from the identity Ed25519 keypair.
    internal static Account DecryptVaultItem(byte[] identityX25519PublicKey, byte[] identityX25519PrivateKey, Model.VaultItem item)
    {
        // 1. Decrypt item key (sealed box with identity X25519)
        var itemEd25519Key = DecryptItemKey(identityX25519PublicKey, identityX25519PrivateKey, item.ItemKey.EncryptedItemPrivateKey.Decode64());

        // 2. Convert item Ed25519 → X25519
        var itemX25519Public = Crypto.Ed25519ToX25519Public(itemEd25519Key[32..]);
        var itemX25519Private = Crypto.Ed25519ToX25519Private(itemEd25519Key);

        // 3. Decrypt value key (sealed box with item X25519)
        var valueKey = DecryptValueKey(itemX25519Public, itemX25519Private, item.EncryptedValueKey.Decode64());

        // 4. Decrypt value (XChaCha20 with value key)
        var outerJson = DecryptItemValue(valueKey, item.Value.Decode64());

        // 5. Parse the outer wrapper {"type":"...","value":"..."} and extract inner JSON
        var wrapper =
            JsonSerializer.Deserialize<Model.DecryptedValueWrapper>(outerJson)
            ?? throw new InternalErrorException("Failed to parse decrypted item wrapper");
        var parsed =
            JsonSerializer.Deserialize<Model.DecryptedValue>(wrapper.Value)
            ?? throw new InternalErrorException("Failed to parse decrypted item value");

        // 6. Map to Account
        return new Account(
            Id: item.ItemId,
            Name: parsed.Title ?? "",
            Username: parsed.Username ?? "",
            Password: parsed.Secret ?? "",
            Url: parsed.Url ?? "",
            Note: parsed.Note ?? ""
        );
    }

    // Decrypts the identity private key using the master key.
    // Returns the raw Ed25519 keypair (64 bytes: 32-byte seed + 32-byte public key).
    internal static byte[] DecryptIdentityKey(byte[] masterKey, byte[] encryptedPrivateKey) =>
        Crypto.DecryptXChaCha20Poly1305(encryptedPrivateKey, masterKey).Decode64();

    // Decrypts the item private key using the identity X25519 keypair (sealed box).
    // Returns the raw Ed25519 keypair (64 bytes: 32-byte seed + 32-byte public key).
    internal static byte[] DecryptItemKey(byte[] identityX25519PublicKey, byte[] identityX25519PrivateKey, byte[] encryptedItemPrivateKey) =>
        Crypto.DecryptSealedBox(encryptedItemPrivateKey, identityX25519PublicKey, identityX25519PrivateKey).Decode64();

    // Decrypts the value key using the item X25519 keypair (sealed box).
    // Returns the 32-byte symmetric key used to decrypt the item value.
    internal static byte[] DecryptValueKey(byte[] itemX25519PublicKey, byte[] itemX25519PrivateKey, byte[] encryptedValueKey) =>
        Crypto.DecryptSealedBox(encryptedValueKey, itemX25519PublicKey, itemX25519PrivateKey).Decode64();

    // Decrypts the item value using the value key (XChaCha20-Poly1305).
    // Returns the decrypted JSON string.
    internal static string DecryptItemValue(byte[] valueKey, byte[] encryptedValue) =>
        Crypto.DecryptXChaCha20Poly1305(encryptedValue, valueKey).ToUtf8();
}
