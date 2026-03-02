// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.NordPass;

public static class Client
{
    public static async Task<Vault> OpenVault(
        string email,
        string masterPassword,
        IAsyncUi ui,
        IAsyncSecureStorage? storage,
        CancellationToken cancellationToken
    )
    {
        using var transport = new RestTransport();
        return await OpenVault(email, masterPassword, ui, storage ?? new NullStorage(), transport, cancellationToken).ConfigureAwait(false);
    }

    //
    // Internal
    //

    internal static async Task<Vault> OpenVault(
        string email,
        string masterPassword,
        IAsyncUi ui,
        IAsyncSecureStorage storage,
        IRestTransport transport,
        CancellationToken cancellationToken
    )
    {
        // 1. Discover the OAuth provider and regional API base for this account
        var providers = await FetchOAuthProviders(email, MakeRestClient(transport), cancellationToken).ConfigureAwait(false);
        var rest = MakeRestClient(transport, GetApiBase(providers.Region));

        // Try to skip the browser flow if we have a stored token
        var storedAuth = await LoadStoredAuth(storage, cancellationToken).ConfigureAwait(false);
        var isAccessTokenValid = storedAuth != null && storedAuth.ExpiresAt > DateTime.UtcNow + TokenRefreshThreshold;
        var isRefreshTokenValid = storedAuth != null && storedAuth.RefreshExpiresAt > DateTime.UtcNow + TokenRefreshThreshold;

        // 2. First try with the access token
        if (isAccessTokenValid)
        {
            rest.AddOrUpdateHeader("Authorization", $"Bearer {storedAuth!.AccessToken}");
            try
            {
                return await GetVault().ConfigureAwait(false);
            }
            catch (TokenExpiredException)
            {
                await ClearAuth().ConfigureAwait(false);
            }
        }

        // 3. If access token is expired but refresh token is still valid, try to refresh and do the same again
        if (isRefreshTokenValid)
        {
            try
            {
                await RefreshAuthToken(storedAuth!.RefreshToken, storage, rest, cancellationToken).ConfigureAwait(false);
                return await GetVault().ConfigureAwait(false);
            }
            catch (TokenExpiredException)
            {
                await ClearAuth().ConfigureAwait(false);
            }
        }

        // 4. Both access and refresh failed, so we do a full OAuth flow now
        await PerformFullLogin(email, providers.Provider, ui, storage, rest, cancellationToken).ConfigureAwait(false);
        return await GetVault().ConfigureAwait(false);

        // ---

        Task<Vault> GetVault() => FetchAndDecryptVault(masterPassword, rest, cancellationToken);

        async Task ClearAuth()
        {
            await storage.DeleteString(AuthKey, cancellationToken).ConfigureAwait(false);
            rest.RemoveHeader("Authorization");
        }
    }

    internal static async Task PerformFullLogin(
        string email,
        string provider,
        IAsyncUi ui,
        IAsyncSecureStorage storage,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // 1. OAuth login
        var (verifier, challenge) = GeneratePkce();
        var deviceId = Common.Crypto.Sha256(Guid.NewGuid().ToByteArray()).ToHex();
        var login = await InitiateOAuthLogin(email, deviceId, challenge, provider, rest, cancellationToken).ConfigureAwait(false);

        // 2. Browser-based authentication
        var verifyToken = await ui.AuthorizeOAuth(login.RedirectUrl, cancellationToken).ConfigureAwait(false);
        if (verifyToken == null)
            throw new CanceledMultiFactorException("OAuth authorization was canceled by the user");

        // 3. Exchange token
        var tokenInfo = await ExchangeToken(verifyToken, login.AttemptId, verifier, rest, cancellationToken).ConfigureAwait(false);
        rest.AddOrUpdateHeader("Authorization", $"Bearer {tokenInfo.AccessToken}");

        // 4. Persist tokens for future sessions
        await StoreAuth(tokenInfo, storage, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<Vault> FetchAndDecryptVault(string masterPassword, RestClient rest, CancellationToken cancellationToken)
    {
        // 1. Fetch identities
        var identities = await FetchIdentities(rest, cancellationToken).ConfigureAwait(false);
        if (identities.Length == 0)
            throw new InternalErrorException("No identities found");

        // TODO: what should we do when there are multiple identities?
        var identity = identities[0];
        if (identity.Keys.Length == 0)
            throw new InternalErrorException("No identity keys found");

        // 2. Fetch vault items for the first identity
        var items = await FetchVaultItems(identity.IdentityId, rest, cancellationToken).ConfigureAwait(false);

        // 3. Decrypt vault
        return DecryptVault(masterPassword, identity.Keys[0], items);
    }

    internal static Vault DecryptVault(string masterPassword, Model.IdentityKey identityKey, Model.VaultItem[] items)
    {
        // Prepare the keys
        var masterKey = Crypto.DeriveKey(masterPassword, identityKey.Salt.Decode64());
        var (x25519Public, x25519Private) = DecryptIdentityX25519KeyPair(masterKey, identityKey.EncryptedPrivateKey.Decode64());

        // Folders are needed to decrypt items
        var folders = DecryptFolders(x25519Public, x25519Private, items);
        var accounts = DecryptItems(x25519Public, x25519Private, folders, items);

        return new Vault(accounts);
    }

    internal record DecryptedFolder(string Name, byte[] Public, byte[] Private, byte[]? SecretPublic, byte[]? SecretPrivate);

    internal static Dictionary<string, DecryptedFolder> DecryptFolders(
        byte[] identityX25519Public,
        byte[] identityX25519Private,
        Model.VaultItem[] items
    )
    {
        var folderItems = items.Where(i => i.Type == "folder").ToArray();
        var folders = new Dictionary<string, DecryptedFolder>();

        // Process folders in dependency order: root folders first (no parent), then nested
        var remaining = new List<Model.VaultItem>(folderItems);
        var previousCount = -1;
        while (remaining.Count > 0 && remaining.Count != previousCount)
        {
            previousCount = remaining.Count;

            // Start from the back to safely remove items while iterating
            for (var i = remaining.Count - 1; i >= 0; i--)
            {
                var item = remaining[i];

                // If parents keys are not yet available leave this folder for now, we'll get back to it later.
                if (!TryResolveParentKeys(item, folders, identityX25519Public, identityX25519Private, out var parentKeys))
                    continue;

                var (folderPublic, folderPrivate) = DecryptItemX25519KeyPair(
                    parentKeys.Public,
                    parentKeys.Private,
                    item.ItemKey.EncryptedItemPrivateKey.Decode64()
                );
                var name = DecryptFolderName(folderPublic, folderPrivate, item);

                // SplitSecret (v1.1.0+): folders have a parallel secret key pair
                byte[]? secretPublic = null;
                byte[]? secretPrivate = null;
                if (item.ItemKey.EncryptedSecretPrivateKey != null)
                    (secretPublic, secretPrivate) = DecryptItemX25519KeyPair(
                        parentKeys.SecretPublic,
                        parentKeys.SecretPrivate,
                        item.ItemKey.EncryptedSecretPrivateKey.Decode64()
                    );

                folders[item.ItemId] = new DecryptedFolder(name, folderPublic, folderPrivate, secretPublic, secretPrivate);
                remaining.RemoveAt(i);
            }
        }

        // TODO: Do we need to allow skipping folders that we cannot decrypt? It's tricky, because this could either mean that we have a bug
        //       or that there's something shared with us, we don't have access to. This needs to be investigated. For now we assume we should
        //       be able to decrypt all folders.
        if (remaining.Count > 0)
            throw new InternalErrorException($"Failed to resolve folder key chain for {remaining.Count} folder(s)");

        return folders;
    }

    internal record ParentKeys(byte[] Public, byte[] Private, byte[] SecretPublic, byte[] SecretPrivate);

    // Returns false when the parent folder hasn't been decrypted yet (used by DecryptFolders to defer).
    internal static bool TryResolveParentKeys(
        Model.VaultItem item,
        Dictionary<string, DecryptedFolder> folders,
        byte[] identityX25519Public,
        byte[] identityX25519Private,
        out ParentKeys keys
    )
    {
        var parentId = item.ItemKey.FolderId;
        if (parentId == null)
        {
            keys = new ParentKeys(identityX25519Public, identityX25519Private, identityX25519Public, identityX25519Private);
            return true;
        }

        if (!folders.TryGetValue(parentId, out var folder))
        {
            keys = null!;
            return false;
        }

        keys = new ParentKeys(
            folder.Public,
            folder.Private,
            folder.SecretPublic ?? identityX25519Public,
            folder.SecretPrivate ?? identityX25519Private
        );
        return true;
    }

    internal static Account?[] DecryptItems(
        byte[] identityX25519Public,
        byte[] identityX25519Private,
        Dictionary<string, DecryptedFolder> folders,
        Model.VaultItem[] items
    ) =>
        items
            .Where(i => i.Type == "item")
            .Select(i =>
            {
                var folderName = folders.GetValueOrDefault(i.ItemKey.FolderId ?? "")?.Name ?? "";
                TryResolveParentKeys(i, folders, identityX25519Public, identityX25519Private, out var keys);
                return DecryptVaultItem(keys!.Public, keys.Private, keys.SecretPublic, keys.SecretPrivate, i, folderName);
            })
            .Where(a => a != null)
            .ToArray();

    internal static readonly Dictionary<string, string> DefaultHeaders = new() { ["nordpass-user-agent"] = "NordPass webvault (7.3.14) webvault" };

    internal static (string Verifier, string Challenge) GeneratePkce()
    {
        var verifier = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var challenge = Common.Crypto.Sha256(verifier.ToBytes()).ToHex();
        return (verifier, challenge);
    }

    internal static RestClient MakeRestClient(IRestTransport transport, string apiBase = DefaultApiBase) =>
        new(transport, apiBase, defaultHeaders: DefaultHeaders, useSystemJson: true);

    internal static string GetApiBase(string region) =>
        region switch
        {
            "eu" => "https://api.eu.nordpass.com",
            _ => DefaultApiBase,
        };

    internal static async Task<Model.OAuthProvidersResponse> FetchOAuthProviders(string email, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.GetAsync<Model.OAuthProvidersResponse>(
                $"v1/users/oauth/providers?email={Uri.EscapeDataString(email)}",
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data;
    }

    internal class TokenExpiredException(string message = "Access token expired") : BaseException(message);

    internal static BaseException MakeError<T>(RestResponse<T> response)
    {
        if (response.IsNetworkError)
            return new NetworkErrorException("Network error", response.Error);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
            return new TokenExpiredException();

        if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound && HasTokenExpiredErrorCode(response))
            return new TokenExpiredException();

        return new InternalErrorException($"Request failed with HTTP {(int)response.StatusCode}");
    }

    internal static bool HasTokenExpiredErrorCode<T>(RestResponse<T> response)
    {
        if (response is not RestResponse<string> { Content: not null } textResponse)
            return false;

        try
        {
            var error = JsonSerializer.Deserialize<Model.ApiErrorResponse>(textResponse.Content);
            return error?.Errors?.Code is 1000 or 1001;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    //
    // OAuth API
    //

    internal static async Task<Model.OAuthLoginResponse> InitiateOAuthLogin(
        string email,
        string deviceId,
        string challenge,
        string provider,
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
                    ["provider"] = provider,
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

    internal record TokenInfo(string AccessToken, DateTime ExpiresAt, string RefreshToken, DateTime RefreshExpiresAt);

    internal static async Task<TokenInfo> ExchangeToken(
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

        var token = response.Data.Token;
        return new TokenInfo(
            AccessToken: token.Token,
            ExpiresAt: ParseNordPassDateTime(token.ExpiresAt),
            RefreshToken: token.RefreshToken,
            RefreshExpiresAt: ParseNordPassDateTime(token.RefreshExpiresAt)
        );
    }

    internal static async Task<bool> RefreshAuthToken(
        string refreshToken,
        IAsyncSecureStorage storage,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.PostJsonAsync<Model.OAuthToken>(
                "v1/users/tokens/renew",
                new Dictionary<string, object> { ["renew_token"] = refreshToken },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        var auth = response.Data;
        var tokenInfo = new TokenInfo(
            AccessToken: auth.Token,
            ExpiresAt: ParseNordPassDateTime(auth.ExpiresAt),
            RefreshToken: auth.RefreshToken,
            RefreshExpiresAt: ParseNordPassDateTime(auth.RefreshExpiresAt)
        );

        rest.AddOrUpdateHeader("Authorization", $"Bearer {tokenInfo.AccessToken}");
        await StoreAuth(tokenInfo, storage, cancellationToken).ConfigureAwait(false);

        return true;
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
                    $"v2/users/identities/items?identity_id={identityId}&type%5B%5D=item&type%5B%5D=folder&type%5B%5D=option&with_secrets=true&page={page}",
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
    // The parent X25519 keys are the identity keys (for root items) or the folder keys (for items in folders).
    // Only items of type "password" are parsed, other types are ignored (return null).
    internal static Account? DecryptVaultItem(
        byte[] parentX25519PublicKey,
        byte[] parentX25519PrivateKey,
        byte[] parentSecretX25519PublicKey,
        byte[] parentSecretX25519PrivateKey,
        Model.VaultItem item,
        string folder
    )
    {
        // 1. Decrypt item key (sealed box with parent X25519)
        var (itemX25519Public, itemX25519Private) = DecryptItemX25519KeyPair(
            parentX25519PublicKey,
            parentX25519PrivateKey,
            item.ItemKey.EncryptedItemPrivateKey.Decode64()
        );

        // 2. Decrypt value key (sealed box with item X25519)
        var valueKey = DecryptValueKey(itemX25519Public, itemX25519Private, item.EncryptedValueKey.Decode64());

        // 3. Decrypt value (XChaCha20 with value key)
        var outerJson = DecryptItemValue(valueKey, item.Value.Decode64());

        // 4. Parse the outer wrapper {"type":"...","value":"..."} and extract inner JSON
        var wrapper =
            JsonSerializer.Deserialize<Model.DecryptedItemWrapper>(outerJson)
            ?? throw new InternalErrorException("Failed to parse decrypted item wrapper");

        // TODO: Do we need to handle other types like "secure_note", "card", etc? For now we only parse "password" items and ignore the rest.
        if (wrapper.Type != "password")
            return null;

        // 5. Parse the value (inner JSON)
        var parsed =
            JsonSerializer.Deserialize<Model.DecryptedPassword>(wrapper.Value)
            ?? throw new InternalErrorException("Failed to parse decrypted password value");

        // 6. For SplitSecret items (v1.1.0+), the secret/note are stored separately and need to be decrypted via the secret keychain.
        var secret = parsed.Secret;
        var note = parsed.Note;
        var customFields = parsed.CustomFields;
        if (item.EncryptedSecret != null && item.ItemKey.EncryptedSecretPrivateKey != null)
        {
            var secretParsed = DecryptSplitSecret(parentSecretX25519PublicKey, parentSecretX25519PrivateKey, item);
            if (secretParsed != null)
            {
                secret ??= secretParsed.Secret;
                note ??= secretParsed.Note;
                customFields ??= secretParsed.CustomFields;
            }
        }

        // 7. Map to Account
        var urls = new[] { parsed.Url }.Concat(parsed.AdditionalUrls ?? []).Where(u => !u.IsNullOrEmpty()).ToArray();
        var mappedCustomFields = customFields?.Select(ParseCustomField).ToArray() ?? [];

        return new Account(
            Id: item.ItemId,
            Name: parsed.Title ?? "",
            Username: parsed.Username ?? "",
            Password: secret ?? "",
            Urls: urls,
            Note: note ?? "",
            Folder: folder,
            CustomFields: mappedCustomFields
        );
    }

    // Decrypts the separate secret for SplitSecret (v1.1.0+) items.
    // The secret private key is sealed with the parent's SECRET key pair (folder secret key or identity key).
    // This is a parallel chain to the regular item keychain.
    // Chain: parent secret key → item secret key pair → secret value key → secret value
    internal static Model.DecryptedPassword? DecryptSplitSecret(
        byte[] parentSecretX25519PublicKey,
        byte[] parentSecretX25519PrivateKey,
        Model.VaultItem item
    )
    {
        // 1. Decrypt secret key pair (sealed box with parent's secret X25519)
        var (secretX25519Public, secretX25519Private) = DecryptItemX25519KeyPair(
            parentSecretX25519PublicKey,
            parentSecretX25519PrivateKey,
            item.ItemKey.EncryptedSecretPrivateKey!.Decode64()
        );

        // 2. Decrypt secret value key (sealed box with secret X25519)
        var secretKey = DecryptValueKey(secretX25519Public, secretX25519Private, item.EncryptedSecretKey!.Decode64());

        // 3. Decrypt the secret value (XChaCha20 with secret key)
        var secretJson = DecryptItemValue(secretKey, item.EncryptedSecret!.Decode64());

        return JsonSerializer.Deserialize<Model.DecryptedPassword>(secretJson);
    }

    internal static CustomField ParseCustomField(Model.DecryptedCustomField field) =>
        new(Name: field.Label ?? "", Value: field.Type == "date" ? ParseDateValue(field.Value ?? "") : field.Value ?? "");

    internal static string ParseDateValue(string value) =>
        long.TryParse(value, out var epoch) ? DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime.ToString("D") : value;

    internal static string DecryptFolderName(byte[] folderX25519PublicKey, byte[] folderX25519PrivateKey, Model.VaultItem folder)
    {
        var valueKey = DecryptValueKey(folderX25519PublicKey, folderX25519PrivateKey, folder.EncryptedValueKey.Decode64());
        var outerJson = DecryptItemValue(valueKey, folder.Value.Decode64());
        var wrapper =
            JsonSerializer.Deserialize<Model.DecryptedItemWrapper>(outerJson)
            ?? throw new InternalErrorException("Failed to parse decrypted folder wrapper");
        var parsed =
            JsonSerializer.Deserialize<Model.DecryptedFolder>(wrapper.Value)
            ?? throw new InternalErrorException("Failed to parse decrypted folder value");
        return parsed.Title ?? "";
    }

    internal static (byte[] Public, byte[] Private) DecryptIdentityX25519KeyPair(byte[] masterKey, byte[] encryptedPrivateKey) =>
        Ed25519ToX25519KeyPair(Crypto.DecryptXChaCha20Poly1305(encryptedPrivateKey, masterKey).Decode64());

    internal static (byte[] Public, byte[] Private) DecryptItemX25519KeyPair(
        byte[] identityX25519PublicKey,
        byte[] identityX25519PrivateKey,
        byte[] encryptedItemPrivateKey
    ) => Ed25519ToX25519KeyPair(Crypto.DecryptSealedBox(encryptedItemPrivateKey, identityX25519PublicKey, identityX25519PrivateKey).Decode64());

    private static (byte[] Public, byte[] Private) Ed25519ToX25519KeyPair(byte[] ed25519Key) =>
        (Crypto.Ed25519ToX25519Public(ed25519Key[32..]), Crypto.Ed25519ToX25519Private(ed25519Key));

    // Decrypts the value key using the item X25519 keypair (sealed box).
    // Returns the 32-byte symmetric key used to decrypt the item value.
    internal static byte[] DecryptValueKey(byte[] itemX25519PublicKey, byte[] itemX25519PrivateKey, byte[] encryptedValueKey) =>
        Crypto.DecryptSealedBox(encryptedValueKey, itemX25519PublicKey, itemX25519PrivateKey).Decode64();

    // Decrypts the item value using the value key (XChaCha20-Poly1305).
    // Returns the decrypted JSON string.
    internal static string DecryptItemValue(byte[] valueKey, byte[] encryptedValue) =>
        Crypto.DecryptXChaCha20Poly1305(encryptedValue, valueKey).ToUtf8();

    //
    // Storage helpers
    //

    private const string AuthKey = "auth";
    private static readonly TimeSpan TokenRefreshThreshold = TimeSpan.FromMinutes(5);

    private static async Task<Model.StoredAuth?> LoadStoredAuth(IAsyncSecureStorage storage, CancellationToken cancellationToken)
    {
        var json = await storage.LoadString(AuthKey, cancellationToken).ConfigureAwait(false);
        if (json.IsNullOrEmpty())
            return null;

        try
        {
            return JsonSerializer.Deserialize<Model.StoredAuth>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Task StoreAuth(TokenInfo tokenInfo, IAsyncSecureStorage storage, CancellationToken cancellationToken) =>
        storage.StoreString(
            AuthKey,
            JsonSerializer.Serialize(
                new Model.StoredAuth
                {
                    AccessToken = tokenInfo.AccessToken,
                    ExpiresAt = tokenInfo.ExpiresAt,
                    RefreshToken = tokenInfo.RefreshToken,
                    RefreshExpiresAt = tokenInfo.RefreshExpiresAt,
                }
            ),
            cancellationToken
        );

    //
    // Helpers
    //

    internal static DateTime ParseNordPassDateTime(string value)
    {
        if (
            DateTime.TryParseExact(
                value,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var result
            )
        )
        {
            return result;
        }

        throw new InternalErrorException($"Failed to parse date/time value: '{value}'");
    }

    //
    // Data
    //

    internal const string DefaultApiBase = "https://api.nordpass.com";
}
