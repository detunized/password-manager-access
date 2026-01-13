// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden;

public static partial class Client
{
    // Default base URLs for different regions.
    // The US region is the default one when no base URL is specified.
    public const string BaseUrlUs = "https://vault.bitwarden.com";
    public const string BaseUrlEu = "https://vault.bitwarden.eu";
    public const string DefaultBaseUlr = BaseUrlUs;

    // Use this function to generate a random device ID. The device ID should be unique to each
    // installation, but it should not be new on every run. A new random device ID should be
    // generated with GenerateRandomDeviceId on the first run and reused later on.
    public static string GenerateRandomDeviceId() => Guid.NewGuid().ToString();

    //
    // Single shot methods
    //

    // The main entry point for a single shot method. Use this function to open the vault in the
    // API mode. In this mode the login is fully non-interactive even with 2FA enabled. Bitwarden
    // servers don't use 2FA in this mode and permit to bypass it. There's no captcha in this mode
    // either. This mode requires credentials that could be found in the vault settings: the client ID and the client secret.
    public static async Task<Vault> Open(ClientInfoApi clientInfo, IAsyncSecureStorage? storage, CancellationToken cancellationToken)
    {
        var session = await LogIn(clientInfo, storage ?? new NullStorage(), cancellationToken).ConfigureAwait(false);
        return await DownloadAndLogOut(session, cancellationToken).ConfigureAwait(false);
    }

    //
    // LogIn, DownloadVault, LogOut sequence
    //

    // This method performs a login in the API mode. The returned session can be used to download
    // the vault, if needed multiple times. When no longer needed LogOut should be called.
    // See single shot Open for more comments.
    public static async Task<Session> LogIn(ClientInfoApi clientInfo, IAsyncSecureStorage? storage, CancellationToken cancellationToken)
    {
        var transport = new RestTransport();
        try
        {
            return await LogInApi(clientInfo, storage ?? new NullStorage(), transport, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            transport.Dispose();
            throw;
        }
    }

    // This method downloads the vault from the server. The session must be obtained from LogIn.
    public static async Task<Vault> DownloadVault(Session session, CancellationToken cancellationToken)
    {
        var encryptedVault = await TryRefreshTokenRetry(() => FetchVault(session.Rest, cancellationToken), session, cancellationToken);
        return DecryptVault(encryptedVault, session.Key);
    }

    // This method logs out the session. Call this when the session is no longer needed.
    // After that the session object could not be used anymore. The behavior is undefined
    // if it's used again.
    public static Task LogOut(Session session, CancellationToken cancellationToken)
    {
        try
        {
            // Bitwarden doesn't require explicit logout, but we clean up resources
            // The session token will naturally expire
        }
        finally
        {
            session.Transport.Dispose();
        }

        return Task.CompletedTask;
    }

    // This method fetches a single item from the vault by its ID. The session must be obtained from LogIn.
    public static async Task<OneOf<Account, SshKey, NoItem>> GetItem(string itemId, Session session, CancellationToken cancellationToken)
    {
        var maybeItem = await TryRefreshTokenRetry(
            () => FetchItemAndMaybeFoldersAndCollections(itemId, session, cancellationToken),
            session,
            cancellationToken
        );

        return maybeItem.Value switch
        {
            Model.Item item => ParseItem(item, session),
            NoItem noItem => noItem,
            _ => throw new InternalErrorException("Logic error"),
        };
    }

    //
    // Internal
    //

    internal static async Task<T> TryRefreshTokenRetry<T>(Func<Task<T>> func, Session session, CancellationToken cancellationToken)
    {
        try
        {
            return await func().ConfigureAwait(false);
        }
        catch (TokenExpiredException)
        {
            // The token is expired, delete it
            await session.Storage.DeleteString(AuthKey, cancellationToken).ConfigureAwait(false);
            session.Rest.RemoveHeader("Authorization");
        }

        if (!await RefreshAuthToken(session, cancellationToken))
            throw new TokenExpiredException("Access token is expired and cannot be refreshed");

        return await func().ConfigureAwait(false);
    }

    internal static async Task<Vault> DownloadAndLogOut(Session session, CancellationToken cancellationToken)
    {
        try
        {
            return await DownloadVault(session, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await LogOut(session, cancellationToken).ConfigureAwait(false);
        }
    }

    internal static async Task<Session> LogInApi(
        ClientInfoApi clientInfo,
        IAsyncSecureStorage storage,
        IRestTransport transport,
        CancellationToken cancellationToken
    )
    {
        var rest = MakeRestClient(clientInfo.BaseUrl, transport);

        // Try to skip the login if we have a stored token from the last time
        var storedAuth = await LoadStoredAuth(storage, cancellationToken).ConfigureAwait(false);
        if (storedAuth != null && storedAuth.ExpiresAt > DateTime.UtcNow + TokenRefreshThreshold)
        {
            try
            {
                // 1. Try to use the stored token. If it's expired, fallthrough to full login.
                rest.AddOrUpdateHeader("Authorization", storedAuth.AuthToken);

                // 2. Get profile
                var encryptedProfile = await FetchProfile(rest, cancellationToken).ConfigureAwait(false);

                // 3. Get KDF info
                var kdfInfo = await GetKdfInfo(encryptedProfile.Email, rest, cancellationToken).ConfigureAwait(false);

                // 4. Decrypt the profile and make a session
                return DecryptProfileToSession(encryptedProfile, clientInfo.Password, kdfInfo, storage, rest, storedAuth.RefreshToken);
            }
            catch (TokenExpiredException)
            {
                // This token is no good anymore, delete it
                await storage.DeleteString(AuthKey, cancellationToken).ConfigureAwait(false);

                // Fallthrough to full login
            }
        }

        // Do full login
        return await LogInApiFull(clientInfo, storage, rest, cancellationToken).ConfigureAwait(false);
    }

    internal static Task<Session> LogInApiFull(
        ClientInfoApi clientInfo,
        IAsyncSecureStorage storage,
        RestClient rest,
        CancellationToken cancellationToken
    ) =>
        LogInGeneric(
            clientInfo.ClientId,
            clientInfo.DeviceId,
            clientInfo.Password,
            new Dictionary<string, string> { ["client_secret"] = clientInfo.ClientSecret, ["grant_type"] = "client_credentials" },
            storage,
            rest,
            cancellationToken
        );

    internal static Task<Session> LogInGeneric(
        string clientId,
        string deviceId,
        string password,
        string baseUrl,
        Dictionary<string, string> extraParameters,
        IAsyncSecureStorage storage,
        IRestTransport transport,
        CancellationToken cancellationToken
    ) => LogInGeneric(clientId, deviceId, password, extraParameters, storage, MakeRestClient(baseUrl, transport), cancellationToken);

    internal static async Task<Session> LogInGeneric(
        string clientId,
        string deviceId,
        string password,
        Dictionary<string, string> extraParameters,
        IAsyncSecureStorage storage,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // 1. Login and get the client info
        var authInfo = await RequestAuthInfo(clientId, deviceId, extraParameters, rest, cancellationToken).ConfigureAwait(false);

        // 2. All the requests from here on are authenticated with the token
        rest.AddOrUpdateHeader("Authorization", authInfo.AuthToken);

        // 3. Store the tokens for the future runs
        await StoreAuth(authInfo, storage, cancellationToken).ConfigureAwait(false);

        // 4. Get profile
        var encryptedProfile = await FetchProfile(rest, cancellationToken).ConfigureAwait(false);

        // 5. Decrypt it and make a session
        return DecryptProfileToSession(encryptedProfile, password, authInfo.KdfInfo, storage, rest, authInfo.RefreshToken);
    }

    internal static async Task<bool> RefreshAuthToken(Session session, CancellationToken cancellationToken)
    {
        if (session.RefreshToken.IsNullOrEmpty())
            return false;

        // Try to use the refresh token
        var response = await session
            .Rest.PostFormAsync<Model.Token>(
                "identity/connect/token",
                new Dictionary<string, object>
                {
                    ["client_id"] = AppName,
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = session.RefreshToken!,
                },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (response.IsSuccessful)
        {
            var token = response.Data;
            var authToken = $"{token.TokenType} {token.AccessToken}";
            var expiresAt = DateTime.UtcNow.AddSeconds(token.ExpiresInSeconds);

            // Update the rest, session and storage
            session.Rest.AddOrUpdateHeader("Authorization", authToken);
            session.RefreshToken = token.RefreshToken;

            await StoreAuth(
                    new Model.Auth
                    {
                        AuthToken = authToken,
                        ExpiresAt = expiresAt,
                        RefreshToken = token.RefreshToken,
                    },
                    session.Storage,
                    cancellationToken
                )
                .ConfigureAwait(false);

            return true;
        }

        return false;
    }

    private static Session DecryptProfileToSession(
        Model.Profile encryptedProfile,
        string password,
        Model.KdfInfo kdfInfo,
        IAsyncSecureStorage storage,
        RestClient rest,
        string? refreshToken = null
    )
    {
        // 1. Derive the master encryption key or KEK (key encryption key)
        var key = Util.DeriveKey(encryptedProfile.Email, password, kdfInfo);

        // 2. Decrypt the profile (it contains the vault key, the orgs and the org keys)
        var profile = DecryptProfile(encryptedProfile, key);

        return new Session(key, profile, storage, rest, rest.Transport) { RefreshToken = refreshToken };
    }

    internal static async Task<Model.KdfInfo> GetKdfInfo(string email, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.PostJsonAsync<Model.KdfInfo>(
                "identity/accounts/prelogin",
                new Dictionary<string, object> { ["email"] = email },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeSpecializedError(response);

        var kdfInfo = response.Data;
        ValidateKdfInfo(kdfInfo);

        return kdfInfo;
    }

    internal static void ValidateKdfInfo(Model.KdfInfo info)
    {
        switch (info.Kdf)
        {
            case Model.KdfMethod.Pbkdf2Sha256:
                if (info.Iterations <= 0)
                    throw new InternalErrorException($"Invalid iteration count: {info.Iterations}");
                break;
            case Model.KdfMethod.Argon2id:
                if (info.Iterations <= 0)
                    throw new InternalErrorException($"Invalid iteration count: {info.Iterations}");
                if (info.Memory <= 0)
                    throw new InternalErrorException($"Invalid memory parameter: {info.Memory}");
                if (info.Parallelism <= 0)
                    throw new InternalErrorException($"Invalid parallelism parameter: {info.Parallelism}");
                break;
            default:
                throw new UnsupportedFeatureException($"KDF method {info.Kdf} is not supported");
        }
    }

    internal record AuthInfo(string AuthToken, DateTime ExpiresAt, string? RefreshToken, Model.KdfInfo KdfInfo);

    internal static async Task<AuthInfo> RequestAuthInfo(
        string clientId,
        string deviceId,
        Dictionary<string, string> extraParameters,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var parameters = new Dictionary<string, object>
        {
            ["client_id"] = clientId,
            ["deviceType"] = DeviceType,
            ["deviceName"] = Platform,
            ["deviceIdentifier"] = deviceId,
            ["scope"] = "api",
        };

        foreach (var kv in extraParameters)
            parameters[kv.Key] = kv.Value;

        var response = await rest.PostFormAsync<Model.TokenKdfInfo>("identity/connect/token", parameters, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessful)
            throw MakeSpecializedError(response);

        var tokenKdf = response.Data;
        var kdfInfo = new Model.KdfInfo
        {
            Kdf = tokenKdf.Kdf,
            Iterations = tokenKdf.KdfIterations,
            Memory = tokenKdf.Memory,
            Parallelism = tokenKdf.Parallelism,
        };
        ValidateKdfInfo(kdfInfo);

        return new AuthInfo(
            $"{tokenKdf.TokenType} {tokenKdf.AccessToken}",
            DateTime.UtcNow.AddSeconds(tokenKdf.ExpiresInSeconds),
            tokenKdf.RefreshToken,
            kdfInfo
        );
    }

    internal static RestClient MakeRestClient(string baseUrl, IRestTransport transport)
    {
        if (baseUrl.IsNullOrEmpty())
            throw new ArgumentException("Base URL must not be null or empty", nameof(baseUrl));

        return new RestClient(transport, baseUrl.TrimEnd('/'), defaultHeaders: DefaultRestHeaders, useSystemJson: true);
    }

    //
    // Fetch/Parse helpers
    //

    internal static async Task<Dictionary<string, string>> FetchAndParseFolders(Session session, CancellationToken cancellationToken)
    {
        var folders = await FetchFolders(session, cancellationToken).ConfigureAwait(false);
        return ParseFolders(folders, session.Profile.VaultKey);
    }

    internal static async Task<Dictionary<string, Collection>> FetchAndParseCollections(Session session, CancellationToken cancellationToken)
    {
        var collections = await FetchCollections(session, cancellationToken).ConfigureAwait(false);
        return ParseCollections(collections, session.Profile.VaultKey, session.Profile.OrgKeys);
    }

    //
    // Fetching data
    //

    internal static Task<Model.Profile> FetchProfile(RestClient rest, CancellationToken cancellationToken) =>
        FetchObject<Model.Profile>("api/accounts/profile", rest, cancellationToken);

    internal static Task<Model.Vault> FetchVault(RestClient rest, CancellationToken cancellationToken) =>
        FetchObject<Model.Vault>("api/sync?excludeDomains=true", rest, cancellationToken);

    internal static async Task<T> FetchObject<T>(string endpoint, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.GetAsync<T>(endpoint, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessful)
            return response.Data;

        throw MakeSpecializedError(response);
    }

    internal static async Task<OneOf<Model.Item, NoItem>> FetchItem(string itemId, Session session, CancellationToken cancellationToken)
    {
        var response = await session.Rest.GetAsync<Model.Item>($"api/ciphers/{itemId}/details", cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessful)
            return response.Data;

        // Special case: the item not found
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return NoItem.NotFound;

        throw MakeSpecializedError(response);
    }

    internal static async Task<OneOf<Model.Item, NoItem>> FetchItemAndMaybeFoldersAndCollections(
        string itemId,
        Session session,
        CancellationToken cancellationToken
    )
    {
        var maybeItem = await FetchItem(itemId, session, cancellationToken).ConfigureAwait(false);
        if (maybeItem.IsT1)
            return maybeItem;

        var item = maybeItem.AsT0;

        // TODO: This could be done in parallel!

        // TODO: There's a chance that the folders are outdated in case they were edited since the last fetch.
        //       Figure out the expiry/refresh logic.
        if (item.FolderId != null && session.Folders == null)
            session.Folders = await FetchAndParseFolders(session, cancellationToken).ConfigureAwait(false);

        // TODO: There's a chance that the collections are outdated in case they were edited since the last fetch.
        //       Figure out the expiry/refresh logic.
        if ((item.CollectionIds?.Length ?? 0) > 0 && session.Collections == null)
            session.Collections = await FetchAndParseCollections(session, cancellationToken).ConfigureAwait(false);

        return item;
    }

    internal static async Task<Model.Folder[]> FetchFolders(Session session, CancellationToken cancellationToken)
    {
        var response = await session.Rest.GetAsync<Model.FolderList>("api/folders", cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessful)
            return response.Data.Folders;

        throw MakeSpecializedError(response);
    }

    internal static async Task<Model.Collection[]> FetchCollections(Session session, CancellationToken cancellationToken)
    {
        var response = await session.Rest.GetAsync<Model.CollectionList>("api/collections", cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessful)
            return response.Data.Collections;

        throw MakeSpecializedError(response);
    }

    //
    // Parsing data
    //

    internal static OneOf<Account, SshKey, NoItem> ParseItem(Model.Item item, Session session)
    {
        if (IsItemDeleted(item))
            return NoItem.Deleted;

        var profile = session.Profile;
        var folders = session.Folders ?? [];
        var collections = session.Collections ?? [];

        return item.Type switch
        {
            Model.ItemType.Login => ParseAccountItem(item, profile.VaultKey, profile.OrgKeys, folders, collections),
            Model.ItemType.SshKey => ParseSshKeyItem(item, profile.VaultKey, profile.OrgKeys, folders, collections),
            _ => NoItem.UnsupportedType,
        };
    }

    internal static bool IsItemDeleted(Model.Item item) => !item.DeletedDate.IsNullOrEmpty();

    internal static Profile DecryptProfile(Model.Profile profile, byte[] key)
    {
        var vaultKey = DecryptVaultKey(profile, key);
        var privateKey = DecryptPrivateKey(profile, vaultKey);
        var organizations = ParseOrganizations(profile.Organizations ?? []).ToDictionary(x => x.Id);
        var orgKeys = privateKey == null ? [] : DecryptOrganizationKeys(profile, privateKey);

        return new Profile(vaultKey, organizations, orgKeys);
    }

    internal static Vault DecryptVault(Model.Vault vault, byte[] key)
    {
        // We ignore the session profile as it might be out of date. It doesn't take long to decrypt everything,
        // given that we're going to parse the whole vault in the next step.
        var profile = DecryptProfile(vault.Profile, key);
        var folders = ParseFolders(vault.Folders, profile.VaultKey);
        var collections = ParseCollections(vault.Collections, profile.VaultKey, profile.OrgKeys);
        var (accounts, sshKeys, errors) = ParseAccounts(vault.Ciphers, profile.VaultKey, profile.OrgKeys, folders, collections);
        return new Vault(accounts, sshKeys, collections.Values.ToArray(), profile.Organizations.Values.ToArray(), errors);
    }

    private static Organization[] ParseOrganizations(Model.Organization[] organizations)
    {
        return organizations.Select(x => new Organization(x.Id, x.Name)).ToArray();
    }

    internal static byte[] DecryptVaultKey(Model.Profile profile, byte[] derivedKey)
    {
        // By default use the derived key, this is true for some old vaults.
        if (profile.Key.IsNullOrEmpty())
            return derivedKey;

        // The newer vaults have a key stored in the profile section. It's encrypted
        // with the derived key, with is effectively a KEK now.
        return DecryptToBytes(profile.Key, derivedKey);
    }

    // Null if not present
    internal static byte[]? DecryptPrivateKey(Model.Profile profile, byte[] vaultKey)
    {
        return profile.PrivateKey.IsNullOrEmpty() ? null : DecryptToBytes(profile.PrivateKey, vaultKey);
    }

    internal static Dictionary<string, byte[]> DecryptOrganizationKeys(Model.Profile profile, byte[] privateKey)
    {
        if (profile.Organizations == null)
            return [];

        return profile.Organizations.ToDictionary(x => x.Id, x => DecryptRsaToBytes(x.Key, privateKey));
    }

    internal static Dictionary<string, string> ParseFolders(Model.Folder[] folders, byte[] key)
    {
        return folders.ToDictionary(i => i.Id, i => DecryptToString(i.Name, key));
    }

    internal static Dictionary<string, Collection> ParseCollections(
        Model.Collection[] collections,
        byte[] vaultKey,
        Dictionary<string, byte[]> orgKeys
    )
    {
        return collections.ToDictionary(
            x => x.Id,
            x => new Collection(
                id: x.Id,
                name: DecryptToString(x.Name, x.OrganizationId.IsNullOrEmpty() ? vaultKey : orgKeys[x.OrganizationId]),
                organizationId: x.OrganizationId ?? "",
                hidePasswords: x.HidePasswords
            )
        );
    }

    internal static (Account[], SshKey[], ParseError[]) ParseAccounts(
        Model.Item[] items,
        byte[] vaultKey,
        Dictionary<string, byte[]> orgKeys,
        Dictionary<string, string> folders,
        Dictionary<string, Collection> collections
    )
    {
        var accounts = new List<Account>(items.Length);
        var sshKeys = new List<SshKey>(items.Length);
        List<ParseError> errors = [];

        foreach (var item in items)
        {
            // Deleted items are ignored
            if (IsItemDeleted(item))
                continue;

            try
            {
                switch (item.Type)
                {
                    case Model.ItemType.Login:
                        accounts.Add(ParseAccountItem(item, vaultKey, orgKeys, folders, collections));
                        break;
                    case Model.ItemType.SshKey:
                        sshKeys.Add(ParseSshKeyItem(item, vaultKey, orgKeys, folders, collections));
                        break;
                }
            }
            catch (Exception e)
            {
                errors.Add(
                    new ParseError(
                        $"Failed to parse a vault item '{item.Id}' of type '{item.Type}'",
                        e.Message,
                        e.StackTrace ?? "Stack trace is not available"
                    )
                );
            }
        }

        return ([.. accounts], [.. sshKeys], errors.ToArray());
    }

    internal static Account ParseAccountItem(
        Model.Item item,
        byte[] vaultKey,
        Dictionary<string, byte[]> orgKeys,
        Dictionary<string, string> folders,
        Dictionary<string, Collection> collections
    )
    {
        var (vaultItem, key) = ParseVaultItem(item, vaultKey, orgKeys, folders, collections);
        var login = item.Login!;

        return new Account
        {
            Id = vaultItem.Id,
            Name = vaultItem.Name,
            Note = vaultItem.Note,
            Folder = vaultItem.Folder,
            CollectionIds = vaultItem.CollectionIds,
            HidePassword = vaultItem.HidePassword,
            CustomFields = vaultItem.CustomFields,

            Username = DecryptToStringOrBlank(login.Username, key),
            Password = DecryptToStringOrBlank(login.Password, key),
            Url = DecryptToStringOrBlank(login.Uri, key),
            Totp = DecryptToStringOrBlank(login.Totp, key),
        };
    }

    internal static SshKey ParseSshKeyItem(
        Model.Item item,
        byte[] vaultKey,
        Dictionary<string, byte[]> orgKeys,
        Dictionary<string, string> folders,
        Dictionary<string, Collection> collections
    )
    {
        var (vaultItem, key) = ParseVaultItem(item, vaultKey, orgKeys, folders, collections);
        var sshKey = item.SshKey!;

        return new SshKey
        {
            Id = vaultItem.Id,
            Name = vaultItem.Name,
            Note = vaultItem.Note,
            Folder = vaultItem.Folder,
            CollectionIds = vaultItem.CollectionIds,
            HidePassword = vaultItem.HidePassword,
            CustomFields = vaultItem.CustomFields,

            PublicKey = DecryptToStringOrBlank(sshKey.PublicKey, key),
            PrivateKey = DecryptToStringOrBlank(sshKey.PrivateKey, key),
            Fingerprint = DecryptToStringOrBlank(sshKey.Fingerprint, key),
        };
    }

    internal static (VaultItem, byte[] key) ParseVaultItem(
        Model.Item item,
        byte[] vaultKey,
        Dictionary<string, byte[]> orgKeys,
        Dictionary<string, string> folders,
        Dictionary<string, Collection> collections
    )
    {
        // The item is encrypted with either the vault key or the org key.
        var key = item.OrganizationId.IsNullOrEmpty() ? vaultKey : orgKeys[item.OrganizationId];

        // Newer items (from approx. Aug 2024) have a unique item key attached.
        if (!item.Key.IsNullOrEmpty())
            key = DecryptToBytes(item.Key, key);

        var parsedItem = new VaultItem
        {
            Id = item.Id,
            Name = DecryptToStringOrBlank(item.Name, key),
            Note = DecryptToStringOrBlank(item.Notes, key),
            Folder = item.FolderId == null ? "" : folders.GetValueOrDefault(item.FolderId, ""),
            CollectionIds = item.CollectionIds ?? [],
            HidePassword = item.CollectionIds != null && ResolveHidePassword(item.CollectionIds, collections),
            CustomFields = ParseCustomFields(item, key),
        };

        return (parsedItem, key);
    }

    internal static CustomField[] ParseCustomFields(Model.Item item, byte[] key)
    {
        return item.Fields?.Select(x => ParseField(x, key, item)).ToArray() ?? [];
    }

    internal static CustomField ParseField(Model.Field field, byte[] key, Model.Item item)
    {
        var name = DecryptToStringOrBlank(field.Name, key);
        var value = DecryptToStringOrBlank(field.Value, key);

        return field.Type switch
        {
            0 or 1 or 2 => new CustomField(name, value),
            3 => new CustomField(name, ResolveLinkedField(field.LinkedId, key, item)),
            _ => throw new UnsupportedFeatureException($"Custom field type {field.Type} is not supported"),
        };
    }

    internal static string ResolveLinkedField(int? fieldLinkedId, byte[] key, Model.Item item)
    {
        return fieldLinkedId switch
        {
            null => "",
            100 => DecryptToStringOrBlank(item.Login?.Username, key),
            101 => DecryptToStringOrBlank(item.Login?.Password, key),
            _ => throw new UnsupportedFeatureException($"Linked field ID {fieldLinkedId} is not supported"),
        };
    }

    internal static bool ResolveHidePassword(string[] collectionIds, Dictionary<string, Collection> collections)
    {
        // Items that don't have any collections associated with them cannot hide their password.
        if (collectionIds.Length == 0)
            return false;

        // Only hide the password when ALL the collections this item is in have "hide password" enabled.
        return collectionIds.All(x => collections.GetValueOrDefault(x)?.HidePasswords == true);
    }

    //
    // Encryption
    //

    internal static byte[] DecryptToBytes(string s, byte[] key)
    {
        return CipherString.Parse(s).Decrypt(key);
    }

    // Looks like the original implementation treats RSA strings differently in some contexts.
    // It seems they ignore some data when it's known to be RSA. Using CipherString.Parse
    // wouldn't work here.
    internal static byte[] DecryptRsaToBytes(string s, byte[] privateKey)
    {
        return CipherString.ParseRsa(s).Decrypt(privateKey);
    }

    internal static string DecryptToString(string s, byte[] key)
    {
        return DecryptToBytes(s, key).ToUtf8();
    }

    // s may be null
    internal static string DecryptToStringOrBlank(string? s, byte[] key)
    {
        return s == null ? "" : DecryptToString(s, key);
    }

    //
    // Error handling
    //

    internal static bool IsHttp4XX(RestResponse response)
    {
        return (int)response.StatusCode / 100 == 4;
    }

    internal class TokenExpiredException(string message) : BaseException(message);

    internal static BaseException MakeSpecializedError(RestResponse<string> response)
    {
        if (response.IsNetworkError)
            return new NetworkErrorException("Network error has occurred", response.Error);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            return new TokenExpiredException("The authentication token is invalid or has expired");

        if (!IsHttp4XX(response))
            return new InternalErrorException($"Unexpected response from the server with status code {response.StatusCode}");

        // It's possible that the original request failed because of the JSON parsing, but we
        // ignore it deliberately to first check for returned errors.
        var error = GetServerError(response);
        if (error == null)
        {
            // Only when the error parsing failed we return the original error.
            if (response.HasError)
                return new InternalErrorException("Network request or response parsing failed", response.Error);

            // We expect some error to be returned by the server.
            return new InternalErrorException("Unexpected response from the server");
        }

        var e = error;
        var message = e.Info?.Message ?? e.Description ?? e.Message ?? e.Id ?? "unknown error";

        if (message.Contains("Username or password is incorrect"))
            return new BadCredentialsException(message);

        if (message.Contains("Two-step token is invalid"))
            return new BadMultiFactorException(message);

        if (e.Id == "invalid_client")
            return new BadCredentialsException("Client ID or secret is incorrect");

        return new InternalErrorException($"Server responded with an error: '{message}'");
    }

    internal static Model.Error? GetServerError(RestResponse<string> response)
    {
        try
        {
            return JsonSerializer.Deserialize<Model.Error>(response.Content ?? "{}");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    //
    // Storage helpers
    //

    private static async Task<Model.Auth?> LoadStoredAuth(IAsyncSecureStorage storage, CancellationToken cancellationToken)
    {
        var json = await storage.LoadString(AuthKey, cancellationToken).ConfigureAwait(false);
        if (json.IsNullOrEmpty())
            return null;

        try
        {
            return JsonSerializer.Deserialize<Model.Auth>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Task StoreAuth(AuthInfo authInfo, IAsyncSecureStorage storage, CancellationToken cancellationToken) =>
        StoreAuth(
            new Model.Auth
            {
                AuthToken = authInfo.AuthToken,
                ExpiresAt = authInfo.ExpiresAt,
                RefreshToken = authInfo.RefreshToken,
            },
            storage,
            cancellationToken
        );

    private static Task StoreAuth(Model.Auth auth, IAsyncSecureStorage storage, CancellationToken cancellationToken) =>
        storage.StoreString(AuthKey, JsonSerializer.Serialize(auth), cancellationToken);

    //
    // Private
    //

    private static string GetPlatform()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "macos";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "linux";

        // Don't crash, just assume Windows
        return "windows";
    }

    private const string AppName = "cli";
    private const string CliVersion = "2025.2.0";

    private const string AuthKey = "auth";
    private static readonly TimeSpan TokenRefreshThreshold = TimeSpan.FromMinutes(5);

    private static readonly string Platform = GetPlatform();
    private static readonly string UserAgent = $"Bitwarden_CLI/{CliVersion} ({Platform.ToUpper()})";

    private static readonly string DeviceType = Platform switch
    {
        "windows" => "23",
        "macos" => "24",
        "linux" => "25",
        _ => throw new InternalErrorException($"Unexpected device name {Platform}"),
    };

    private static readonly Dictionary<string, string> DefaultRestHeaders =
        new()
        {
            ["User-Agent"] = UserAgent,
            ["Device-Type"] = DeviceType,
            ["Bitwarden-Client-Name"] = AppName,
            ["Bitwarden-Client-Version"] = CliVersion,
        };
}
