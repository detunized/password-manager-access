// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.NordPass;

public static class Client
{
    public const string ApiBase = "https://api.nordpass.com";

    public static async Task<Vault> OpenVault(string email, string masterPassword, IAsyncUi ui, CancellationToken cancellationToken)
    {
        using var transport = new RestTransport();
        return await OpenVault(email, masterPassword, ui, transport, cancellationToken).ConfigureAwait(false);
    }

    //
    // Internal
    //

    internal static async Task<Vault> OpenVault(
        string email,
        string masterPassword,
        IAsyncUi ui,
        IRestTransport transport,
        CancellationToken cancellationToken
    )
    {
        var rest = MakeRestClient(transport);

        // 1. OAuth login
        var (verifier, challenge) = GeneratePkce();
        var deviceId = Common.Crypto.Sha256(Guid.NewGuid().ToByteArray()).ToHex();
        var login = await InitiateOAuthLogin(email, deviceId, challenge, rest, cancellationToken).ConfigureAwait(false);

        // 2. Browser-based authentication
        var verifyToken = await ui.AuthorizeOAuth(login.RedirectUrl, cancellationToken).ConfigureAwait(false);
        if (verifyToken == null)
            throw new CanceledMultiFactorException("OAuth authorization was canceled by the user");

        // 3. Exchange token
        var accessToken = await ExchangeToken(verifyToken, login.AttemptId, verifier, rest, cancellationToken).ConfigureAwait(false);
        rest.AddOrUpdateHeader("Authorization", $"Bearer {accessToken}");

        // 4. Fetch identities and derive master key
        var identities = await FetchIdentities(rest, cancellationToken).ConfigureAwait(false);
        if (identities.Length == 0)
            throw new InternalErrorException("No identities found");

        var identity = identities[0];
        if (identity.Keys.Length == 0)
            throw new InternalErrorException("No identity keys found");

        var identityKey = identity.Keys[0];

        // 5. Fetch and decrypt vault items
        var items = await FetchVaultItems(identity.IdentityId, rest, cancellationToken).ConfigureAwait(false);

        return DecryptVault(masterPassword, identityKey, items);
    }

    internal static Vault DecryptVault(string masterPassword, Model.IdentityKey identityKey, Model.VaultItem[] items)
    {
        var salt = identityKey.Salt.Decode64();
        var masterKey = Crypto.DeriveKey(masterPassword, salt);
        var identityEd25519Key = DecryptIdentityKey(masterKey, identityKey.EncryptedPrivateKey.Decode64());
        var x25519Public = Crypto.Ed25519ToX25519Public(identityEd25519Key[32..]);
        var x25519Private = Crypto.Ed25519ToX25519Private(identityEd25519Key);

        // Decrypt folder keys (items inside folders are sealed with the folder's key)
        var folderKeys = new Dictionary<string, (byte[] Public, byte[] Private)>();
        foreach (var folder in items.Where(i => i.Type == "folder"))
        {
            var folderEd25519Key = DecryptItemKey(x25519Public, x25519Private, folder.ItemKey.EncryptedItemPrivateKey.Decode64());
            var folderX25519Public = Crypto.Ed25519ToX25519Public(folderEd25519Key[32..]);
            var folderX25519Private = Crypto.Ed25519ToX25519Private(folderEd25519Key);
            folderKeys[folder.ItemId] = (folderX25519Public, folderX25519Private);
        }

        var accounts = items
            .Where(i => i.Type == "item")
            .Select(i =>
            {
                var folderId = i.ItemKey.FolderId;
                if (folderId != null && folderKeys.TryGetValue(folderId, out var fk))
                    return DecryptVaultItem(fk.Public, fk.Private, i);
                return DecryptVaultItem(x25519Public, x25519Private, i);
            })
            .ToArray();

        return new Vault(accounts);
    }

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
    // OAuth API
    //

    internal static async Task<Model.OAuthLoginResponse> InitiateOAuthLogin(
        string email,
        string deviceId,
        string challenge,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.PostJsonAsync<Model.OAuthLoginResponse>(
                "v1/users/oauth/login",
                new Dictionary<string, object>
                {
                    ["challenge"] = challenge,
                    ["redirect_uri"] = "https://app.nordpass.com/login",
                    ["preferred_flow"] = "login",
                    ["provider"] = "nord_account",
                    ["dark_mode"] = false,
                    ["language"] = "en",
                    ["login_url"] = "https://app.nordpass.com/login",
                    ["email"] = email,
                    ["device"] = deviceId,
                    ["platform_id"] = 600,
                    ["browser"] = "chrome",
                    ["os"] = "wasm",
                    ["redirect_upon_open"] = true,
                    ["issued_for"] = "vault",
                },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data;
    }

    internal static async Task<string> ExchangeToken(
        string verifyToken,
        string attemptId,
        string verifier,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.PostJsonAsync<Model.OAuthTokenResponse>(
                "v1/users/oauth/token",
                new Dictionary<string, object>
                {
                    ["verify_token"] = verifyToken,
                    ["attempt_id"] = attemptId,
                    ["verifier"] = verifier,
                },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data.Token.Token;
    }

    //
    // Data fetching
    //

    internal static async Task<Model.Identity[]> FetchIdentities(RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.GetAsync<Model.Identity[]>("v2/users/identities", cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data;
    }

    internal static async Task<Model.VaultItem[]> FetchVaultItems(string identityId, RestClient rest, CancellationToken cancellationToken)
    {
        var items = new List<Model.VaultItem>();
        var page = 1;

        while (true)
        {
            var response = await rest.GetAsync<Model.VaultItemsResponse>(
                    $"v2/users/identities/items?identity_id={identityId}&type%5B%5D=item&type%5B%5D=folder&type%5B%5D=option&page={page}",
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Items.Length == 0)
                break;

            items.AddRange(response.Data.Items);
            page++;
        }

        return items.ToArray();
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
