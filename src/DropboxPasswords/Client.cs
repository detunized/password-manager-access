// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
// TODO: NaCl.net is licensed under the MPL 2.0 license. Best would be to have a MIT licensed version.
using NaCl;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.DropboxPasswords.Response;

namespace PasswordManagerAccess.DropboxPasswords
{
    internal static class Client
    {
        // TODO: Refactor this and clean it up. This is work in progress.
        // TODO: Add error handling everywhere!
        public static Account[] OpenVault(string username, string deviceId, IUi ui, ISecureStorage storage, IRestTransport transport)
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var oauthToken = storage.LoadString(OAuthTokenKey);
                if (oauthToken.IsNullOrEmpty())
                {
                    oauthToken = AcquireOAuthToken(ui, transport);
                    storage.StoreString(OAuthTokenKey, oauthToken);
                }

                var apiRest = new RestClient(transport,
                                             "https://api.dropboxapi.com/2",
                                             defaultHeaders: new Dictionary<string, string>
                                             {
                                                 ["Authorization"] = $"Bearer {oauthToken}",
                                                 ["Origin"] = "chrome-extension://bmhejbnmpamgfnomlahkonpanlkcfabg",
                                             });
                try
                {
                    // Normally we would use the master key to decrypt the vault. In case we don't have it, we need to enroll
                    // a new device and receive the key form one of the devices enrolled previously. To do that we send the
                    // public key to the server which passes it along to one of the devices. The device encrypts the master key
                    // end sends it back to us.
                    var masterKey = LoadMasterKey(storage);
                    var keyset = LoadKeyset(storage);
                    if (masterKey == null || keyset == null)
                    {
                        (masterKey, keyset) = EnrollNewDevice(deviceId, storage, transport, apiRest);
                        storage.StoreString(MasterKeyKey, masterKey.ToBase64());
                        storage.StoreString(KeysetKey, JsonConvert.SerializeObject(keyset));
                    }

                    // 1. Get account info
                    var accountInfo = Post<R.AccountInfo>("users/get_current_account",
                                                          RestClient.JsonNull, // Important to send null!
                                                          RestClient.NoHeaders,
                                                          apiRest);
                    if (accountInfo.Disabled)
                        throw new InternalErrorException("The account is disabled");

                    // 2. Get features
                    var features = Post<R.Features>("passwords/get_features_v2",
                                                    RestClient.JsonNull, // Important to send null!
                                                    RestClient.NoHeaders,
                                                    apiRest);
                    if (features.Eligibility.Tag != "enabled")
                        throw new InternalErrorException("Dropbox Passwords is not enabled on this account");

                    // 3. List the root folder
                    // TODO: Very long folders are not supported. See "has_more" and "cursor".
                    var rootFolder = Post<R.RootFolder>("files/list_folder",
                                                        new Dictionary<string, object> {["path"] = ""},
                                                        MakeRootPathHeaders(features.Eligibility.RootPath),
                                                        apiRest);

                    // 4. Get all entries
                    var contentRest = new RestClient(apiRest.Transport,
                                                     "https://content.dropboxapi.com/2",
                                                     defaultHeaders: apiRest.DefaultHeaders);
                    var entries = DownloadAllEntries(rootFolder, features.Eligibility.RootPath, contentRest);

                    // Try to find all keysets that decrypt (normally there's only one).
                    var keysets = FindAndDecryptAllKeysets(entries, Util.HashMasterKey(masterKey));

                    // Try to decrypt all account entries and see what decrypts.
                    var accounts = FindAndDecryptAllAccounts(entries, keysets);

                    // Done, phew!
                    return accounts;
                }
                catch (TokenExpiredException e)
                {
                    if (attempt == 0)
                    {
                        storage.StoreString(OAuthTokenKey, null);
                        continue;
                    }

                    throw new InternalErrorException("Failed to open the vault", e);
                }
            }

            return Array.Empty<Account>();
        }

        // Returns the master key on successful enrollment.
        private static (byte[] masterKey, R.EncryptedEntry keyset) EnrollNewDevice(string deviceId,
                                                                                   ISecureStorage storage,
                                                                                   IRestTransport transport,
                                                                                   RestClient apiRest)
        {
            // To enroll we need to generate a key pair. The public key will be sent to the server.
            // These keys don't need to persist since we don't do anything else but enrolling the device with them.
            // We can throw them away after we're done.
            var (publicKey, privateKey) = CryptoBoxKeypair();

            // 1. Initial enrollment request which sends the notification to other devices to prompt the user to approve
            var enrollStatus = Post<R.EnrollStatus>("passwords/enroll_device",
                                                    new Dictionary<string, object>
                                                    {
                                                        ["device_id"] = deviceId,
                                                        ["device_public_key"] = publicKey.ToBase64(),
                                                        ["client_ts_ms_utc"] = Os.UnixSeconds(),
                                                        ["app_version"] = "3.23.1",
                                                        ["platform"] = "chrome",
                                                        ["platform_version"] = "Chrome 115.0.0.0",
                                                        ["device_name"] = "Chrome Mac OS",
                                                        ["enroll_action"] = new Dictionary<string, string>
                                                        {
                                                            [".tag"] = "enroll_device"
                                                        },
                                                        ["build_channel"] = new Dictionary<string, string>
                                                        {
                                                            [".tag"] = "external"
                                                        }
                                                    },
                                                    RestClient.NoHeaders,
                                                    apiRest);

            // TODO: Notify the the UI to tell the user to approve on another device

            // 2. We need to request this to get the root path to be used in the follow up requests
            var features = Post<R.Features>("passwords/get_features_v2",
                                            RestClient.JsonNull, // Important to send null!
                                            RestClient.NoHeaders,
                                            apiRest);

            var contentRest = new RestClient(apiRest.Transport,
                                             "https://content.dropboxapi.com/2",
                                             defaultHeaders: apiRest.DefaultHeaders);

            // 3. Download the encrypted keyset that decrypts the vault. To decrypt it we need to also get the master key.
            var keysetResponse = contentRest.PostRaw("passwords/download",
                                                     "",
                                                     MakePathHeaders($"/{enrollStatus.ActiveKeysetName}.json",
                                                                     features.Eligibility.RootPath));
            if (!keysetResponse.IsSuccessful)
                throw new InternalErrorException("Failed to download the master keyset");

            // TODO: 3. Send the ack

            // 4. Get Bolt credentials that are used to subscribe to a Bolt channel to receive the master key
            var boltInfo = Post<R.BoltInfo>("passwords/get_bolt_info",
                                            new Dictionary<string, object>
                                            {
                                                ["device_id"] = deviceId,
                                            },
                                            RestClient.NoHeaders,
                                            apiRest);

            var thunderRest = new RestClient(transport,
                                             "https://thunder.dropbox.com/2",
                                             defaultHeaders: apiRest.DefaultHeaders);

            // 5. Subscribe to a Bolt channel to receive the encrypted master key
            var keys = PostDynamicJson("payloads/subscribe",
                                       new Dictionary<string, object>
                                       {
                                           ["channel_states"] = new[]
                                           {
                                               new Dictionary<string, object>
                                               {
                                                   ["channel_id"] = new Dictionary<string, object>
                                                   {
                                                       ["app_id"] = "passwords_bolt",
                                                       ["unique_id"] = boltInfo.UniqueId,
                                                   },
                                                   ["revision"] = boltInfo.Revision,
                                                   ["token"] = boltInfo.Token,
                                               }
                                           }
                                       },
                                       RestClient.NoHeaders,
                                       thunderRest);

            var payload = keys.SelectToken("$.channel_payloads[0].payloads[0].payload");
            if (payload == null)
                throw new InternalErrorException("Failed to enroll the device");

            var sourceDevicePublicKey = payload.StringAt("source_device_public_key", null);
            var encryptedData = payload.SelectToken("encrypted_user_key_bundle.encrypted_data")?.ToString();
            var nonce = payload.SelectToken("encrypted_user_key_bundle.nonce")?.ToString();

            if (sourceDevicePublicKey == null || encryptedData == null || nonce == null)
                throw new InternalErrorException("Failed to extract the public key and the encrypted master key");

            // Unlock the master key
            var masterKey = CryptoBoxOpenEasy(encryptedData.Decode64(),
                                              nonce.Decode64(),
                                              privateKey,
                                              sourceDevicePublicKey.Decode64());

            return (masterKey, ParseKeyset(keysetResponse.Content) ?? throw new InternalErrorException("Failed to parse the keyset"));
        }

        private static string AcquireOAuthToken(IUi ui, IRestTransport transport)
        {
            // 1. Generate PKCE challenge
            var (verifier, challenge) = GenerateOAuth2PkceValues();

            // 2. Perform OAuth2 login. On success the browser will be redirected to a URL with a code. Example:
            //    https://www.dropbox.com/passwords_extension/auth_redirect?code=QTyFLnr4PfgAAAAAAAAAwFlYxU9pqEhQ6dMUo7nAju0
            var redirectUrl = ui.PerformOAuthLogin(GenerateOAuth2AuthenticationUrl(challenge),
                                                   "https://www.dropbox.com/passwords_extension/auth_redirect");
            if (redirectUrl.IsNullOrEmpty())
                throw new InternalErrorException("Failed to perform OAuth2 login");

            // 3. Parse redirect URL and extract the code
            var code = ExtractQueryParameter(redirectUrl, "code");
            if (code.IsNullOrEmpty())
                throw new InternalErrorException("Invalid redirect URL. Missing auth code");

            // 3. Exchange the code for an OAuth2 token via a POST to:
            var rest = new RestClient(transport, "https://api.dropboxapi.com/oauth2");
            var response = rest.PostForm<R.OAuth2Token>("token",
                                                        new Dictionary<string, object>
                                                        {
                                                            ["grant_type"] = "authorization_code",
                                                            ["code"] = code,
                                                            ["client_id"] = ClientId,
                                                            ["code_verifier"] = verifier,
                                                            ["redirect_uri"] = "https://www.dropbox.com/passwords_extension/auth_redirect",
                                                        },
                                                        RestClient.NoHeaders);

            if (!response.IsSuccessful)
                throw new InternalErrorException("Failed to exchange auth code for an OAuth2 token");

            return response.Data.AccessToken;
        }

        internal static byte[]? LoadMasterKey(ISecureStorage storage)
        {
            var masterKeyString = storage.LoadString(MasterKeyKey) ?? "";
            var masterKey = masterKeyString.Decode64();
            return masterKey.Length == MasterKeySize ? masterKey : null;
        }

        internal static R.EncryptedEntry? LoadKeyset(ISecureStorage storage)
        {
            return ParseKeyset(storage.LoadString(KeysetKey) ?? "");
        }

        private static Response.EncryptedEntry? ParseKeyset(string json)
        {
            try
            {
                return JsonConvert.DeserializeObject<Response.EncryptedEntry>(json);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        internal static (byte[] PublicKey, byte[] PrivateKey) LoadOrGenerateKeys(ISecureStorage storage)
        {
            var (publicKey, privateKey) = LoadKeys(storage);
            if (publicKey != null && privateKey != null)
                return (publicKey, privateKey);

            GenerateAndStoreKeys(storage);
            return LoadKeys(storage)!;
        }

        internal static (byte[]? PublicKey, byte[]? PrivateKey) LoadKeys(ISecureStorage storage)
        {
            var publicKeyString = storage.LoadString(PublicKeyKey) ?? "";
            var privateKeyString = storage.LoadString(PrivateKeyKey) ?? "";
            var publicKey = publicKeyString.Decode64();
            var privateKey = privateKeyString.Decode64();
            if (publicKey.Length != PublicKeySize || privateKey.Length != PrivateKeySize)
                return (null, null);

            return (publicKey, privateKey);
        }

        internal static void GenerateAndStoreKeys(ISecureStorage storage)
        {
            var (publicKey, privateKey) = CryptoBoxKeypair();
            storage.StoreString(PublicKeyKey, publicKey.ToBase64());
            storage.StoreString(PrivateKeyKey, privateKey.ToBase64());
        }

        internal static (byte[] PublicKey, byte[] PrivateKey) CryptoBoxKeypair()
        {
            Curve25519XSalsa20Poly1305.KeyPair(out var privateKey, out var publicKey);
            if (publicKey.Length != PublicKeySize || privateKey.Length != PrivateKeySize)
                throw new InternalErrorException("Invalid key length");

            return (publicKey, privateKey);
        }

        public static byte[] CryptoBoxOpenEasy(byte[] ciphertext, byte[] nonce, byte[] ourPrivateKey, byte[] theirPublicKey)
        {
            var plain = new byte[ciphertext.Length - XSalsa20Poly1305.TagLength];
            if (new Curve25519XSalsa20Poly1305(ourPrivateKey, theirPublicKey).TryDecrypt(plain, ciphertext, nonce))
                return plain;

            throw new CryptoException("Failed to decrypt");
        }

        // TODO: Move to Common
        internal static string ExtractQueryParameter(string url, string name)
        {
            var nameEquals = name + '=';
            var start = url.IndexOf(nameEquals, StringComparison.Ordinal);
            if (start < 0)
                return null;

            start += nameEquals.Length;
            var end = url.IndexOf('&', start);

            return end < 0
                ? url.Substring(start) // The last parameter
                : url.Substring(start, end - start);
        }

        // App info
        internal const string ClientId = "8ho1d12ibryh3ez";

        // Storage keys
        internal const string PublicKeyKey = "public-key";
        internal const string PrivateKeyKey = "private-key";
        internal const string OAuthTokenKey = "oauth-token";
        internal const string MasterKeyKey = "master-key";
        internal const string KeysetKey = "keyset";

        internal const int PublicKeySize = 32;
        internal const int PrivateKeySize = 32;
        internal const int MasterKeySize = 16;

        internal static string GenerateOAuth2AuthenticationUrl(string challenge)
        {
            return "https://dropbox.com/oauth2/authorize?" +
                   "response_type=code&" +
                   $"client_id={ClientId}&" +
                   "redirect_uri=https://www.dropbox.com/passwords_extension/auth_redirect&" +
                   "token_access_type=legacy&" +
                   "code_challenge_method=S256&" +
                   $"code_challenge={challenge}&" +
                   "locale=en";
        }

        internal static (string Verifier, string Challenge) GenerateOAuth2PkceValues()
        {
            return GenerateOAuth2PkceValues(Crypto.RandomBytes(128));
        }

        internal static (string Verifier, string Challenge) GenerateOAuth2PkceValues(byte[] entropy)
        {
            var verifier = entropy.Select(x => x.ToString("D"))
                .JoinToString(",")
                .ToUrlSafeBase64NoPadding()
                .Substring(0, 128);
            var challenge = Crypto.Sha256(verifier)
                .ToUrlSafeBase64NoPadding();

            return (verifier, challenge);
        }

        //--------------------------------------------------------------------------------------------------------------

        public static Account[] OpenVault(string oauthToken, string[] recoveryWords, IRestTransport transport)
        {
            // We do this first to fail early in case the recovery words are incorrect.
            var masterKey = Util.DeriveMasterKeyFromRecoveryWords(recoveryWords);

            var rest = new RestClient(transport,
                                      "https://api.dropboxapi.com/2",
                                      defaultHeaders: new Dictionary<string, string>
                                      {
                                          ["Authorization"] = $"Bearer {oauthToken}"
                                      });

            // 1. Get account info
            var accountInfo = Post<R.AccountInfo>("users/get_current_account",
                                                  RestClient.JsonNull, // Important to send null!
                                                  RestClient.NoHeaders,
                                                  rest);
            if (accountInfo.Disabled)
                throw new InternalErrorException("The account is disabled");

            // 2. Get features
            var features = Post<R.Features>("passwords/get_features_v2",
                                            RestClient.JsonNull, // Important to send null!
                                            RestClient.NoHeaders,
                                            rest);
            if (features.Eligibility.Tag != "enabled")
                throw new InternalErrorException("Dropbox Passwords is not enabled on this account");

            // 3. List the root folder
            // TODO: Very long folders are not supported. See "has_more" and "cursor".
            var rootFolder = Post<R.RootFolder>("files/list_folder",
                                                new Dictionary<string, object> {["path"] = ""},
                                                MakeRootPathHeaders(features.Eligibility.RootPath),
                                                rest);

            // 4. Get all entries
            var contentRest = new RestClient(rest.Transport,
                                             "https://content.dropboxapi.com/2",
                                             defaultHeaders: rest.DefaultHeaders);
            var entries = DownloadAllEntries(rootFolder, features.Eligibility.RootPath, contentRest);

            // Try to find all keysets that decrypt (normally there's only one).
            var keysets = FindAndDecryptAllKeysets(entries, masterKey);

            // Try to decrypt all account entries and see what decrypts.
            var accounts = FindAndDecryptAllAccounts(entries, keysets);

            // Done, phew!
            return accounts;
        }

        //
        // Internal
        //

        internal static R.EncryptedEntry[] DownloadAllEntries(R.RootFolder rootFolder,
                                                              string rootPath,
                                                              RestClient contentRest)
        {
            return rootFolder.Entries
                .AsParallel() // Download in parallel
                .Where(e => e.IsDownloadable && e.Tag == "file")
                .Select(e => DownloadFolderEntry(e.Path, rootPath, contentRest))
                .ToArray(); // This will force the actual download
        }

        internal static R.Keyset[] FindAndDecryptAllKeysets(R.EncryptedEntry[] entries, byte[] masterKey)
        {
            return entries
                .Where(e => e.Type == "keyset")
                .Select(e => DecryptKeyset(e, masterKey))
                .ToArray();
        }

        internal static Account[] FindAndDecryptAllAccounts(R.EncryptedEntry[] entries, R.Keyset[] keysets)
        {
            var keys = ExtractAllKeys(keysets);
            return entries
                .Where(e => e.Type == "password")
                .SelectMany(e => DecryptAccounts(e, keys))
                .ToArray();
        }

        internal static IEnumerable<Account> DecryptAccounts(R.EncryptedEntry entry, Dictionary<string, byte[]> keys)
        {
            // Important: key lookup must be case insensitive! There's a case mismatch in the parsed JSON.
            if (!keys.TryGetValue(entry.Id.ToLower(), out var key))
                return Array.Empty<Account>();

            var folder = DecryptVaultFolder(entry, key);
            return folder.Items
                .Where(x => !x.IsDeleted)
                .Select(x => new Account(id: x.Id ?? "",
                                         name: x.Name ?? "",
                                         username: x.Username ?? "",
                                         password: x.Password ?? "",
                                         url: x.Url ?? "",
                                         note: x.Note ?? "",
                                         folder: folder.Name ?? ""));
        }

        internal static Dictionary<string, byte[]> ExtractAllKeys(R.Keyset[] keysets)
        {
            // Important: the keys must be lowercased! There's a case mismatch in the parsed JSON.
            return keysets
                .SelectMany(ks => ks.Keys.Select(k => (k.Key, k.Value.KeyBase64)))
                .ToDictionary(x => x.Key.ToLower(), x => x.KeyBase64.Decode64());
        }

        //
        // Network
        //

        internal static R.EncryptedEntry DownloadFolderEntry(string path, string rootPath, RestClient rest)
        {
            var response = rest.PostRaw("files/download", "", MakePathHeaders(path, rootPath));
            if (!response.IsSuccessful)
                throw MakeError(response);

            return Deserialize<R.EncryptedEntry>(response.Content);
        }

        internal static Dictionary<string, string> MakeRootPathHeaders(string rootPath)
        {
            return new Dictionary<string, string>
            {
                ["Dropbox-API-Path-Root"] = JsonConvert.SerializeObject(new Dictionary<string, string>
                {
                    [".tag"] = "namespace_id",
                    ["namespace_id"] = rootPath,
                }),
            };
        }

        internal static Dictionary<string, string> MakePathHeaders(string path, string rootPath)
        {
            return MakeRootPathHeaders(rootPath).MergeCopy(new Dictionary<string, string>
            {
                ["Dropbox-API-Arg"] = JsonConvert.SerializeObject(new Dictionary<string, string>
                {
                    ["path"] = path,
                }),
            });
        }

        internal static T Post<T>(string endpoint,
                                  Dictionary<string, object> parameters,
                                  Dictionary<string, string> headers,
                                  RestClient rest)
        {
            var response = rest.PostJson<T>(endpoint: endpoint,
                                            parameters: parameters,
                                            headers: headers);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data;
        }

        // This returns a parsed JSON response in a form suitable for dynamic querying via
        // SelectToken or JToken.*At functions.
        internal static JToken PostDynamicJson(string endpoint,
                                               Dictionary<string, object> parameters,
                                               Dictionary<string, string> headers,
                                               RestClient rest)
        {
            var response = rest.PostJson(endpoint: endpoint,
                                         parameters: parameters,
                                         headers: headers);
            if (!response.IsSuccessful)
                throw MakeError(response);

            try
            {
                return JToken.Parse(response.Content);
            }
            catch (Exception e)
            {
                throw MakeDeserializeError<JToken>(e);
            }
        }

        //
        // Crypto
        //

        internal static R.Keyset DecryptKeyset(R.EncryptedEntry entry, byte[] key)
        {
            return Deserialize<R.Keyset>(Decrypt(entry.EncryptedBundle, key));
        }

        internal static R.VaultFolder DecryptVaultFolder(R.EncryptedEntry entry, byte[] key)
        {
            return Deserialize<R.VaultFolder>(Decrypt(entry.EncryptedBundle, key));
        }

        internal static byte[] Decrypt(R.EncryptedBundle encrypted, byte[] key)
        {
            return Crypto.DecryptXChaCha20Poly1305(encrypted.CiphertextBase64.Decode64(),
                                                   encrypted.NonceBase64.Decode64(),
                                                   key);
        }

        internal static T Deserialize<T>(byte[] json)
        {
            return Deserialize<T>(json.ToUtf8());
        }

        internal static T Deserialize<T>(string json)
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(json) ?? throw MakeDeserializeError<T>();
            }
            catch (JsonException e)
            {
                throw MakeDeserializeError<T>(e);
            }
        }

        //
        // Errors
        //

        internal class TokenExpiredException: Exception
        {
        }

        internal static InternalErrorException MakeError(RestResponse<string> response)
        {
            // Try to deserialize the error response first
            try
            {
                var error = JsonConvert.DeserializeObject<Response.Error>(response.Content);
                if (error != null && error.Status.Tag == "invalid_access_token")
                    throw new TokenExpiredException();
            }
            catch (JsonException)
            {
                // Ignore the failed attempt to deserialize the error response and return a generic error below
            }

            return MakeError($"POST request to {response.RequestUri} failed");
        }

        internal static InternalErrorException MakeError(string message, Exception? inner = null)
        {
            return new InternalErrorException(message, inner);
        }

        internal static InternalErrorException MakeDeserializeError<T>(Exception? inner = null)
        {
            return MakeError($"Failed to deserialize {typeof(T)} from JSON in response", inner);
        }
    }
}
