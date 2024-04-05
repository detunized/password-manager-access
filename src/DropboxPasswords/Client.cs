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
        // TODO: Add error handling everywhere!
        // The `recoveryWords` parameter is optional (could be empty, no nulls please). If it's provided we don't use
        // the master key request and don't store it. It's too involved to create multiple overloads for that.
        public static Account[] OpenVault(ClientInfo clientInfo, string[] recoveryWords, IUi ui, ISecureStorage storage, IRestTransport transport)
        {
            try
            {
                // We allow one attempt to fail due to an expired token. If it fails again we give up.
                return OpenVaultAttempt(clientInfo, recoveryWords, ui, storage, transport);
            }
            catch (TokenExpiredException)
            {
                storage.StoreString(OAuthTokenKey, null);
            }

            return OpenVaultAttempt(clientInfo, recoveryWords, ui, storage, transport);
        }

        //
        // Internal
        //

        internal static Account[] OpenVaultAttempt(ClientInfo clientInfo,
                                                   string[] recoveryWords,
                                                   IUi ui,
                                                   ISecureStorage storage,
                                                   IRestTransport transport)
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

            // Normally we would use the master key to decrypt the vault. In case we don't have it, we need to enroll
            // a new device and receive the key form one of the devices enrolled previously. To do that we send the
            // public key to the server which passes it along to one of the devices. The device encrypts the master key
            // end sends it back to us. We need to to all of that unless the master key is provided in a form of the
            // recovery words. In that case we don't store anything.
            // TODO: Consider storing the master key in the secure storage based on the user's settings.
            var masterKey = recoveryWords.Length > 0
                ? Util.DeriveMasterKeyFromRecoveryWords(recoveryWords)
                : LoadMasterKey(storage);
            if (masterKey == null)
            {
                masterKey = EnrollNewDevice(clientInfo, ui, transport, apiRest);
                storage.StoreString(MasterKeyKey, masterKey.ToBase64());
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
                                                new Dictionary<string, object> { ["path"] = "" },
                                                MakeRootPathHeaders(features.Eligibility.RootPath),
                                                apiRest);

            // 4. Get all entries
            var contentRest = new RestClient(apiRest.Transport,
                                             "https://content.dropboxapi.com/2",
                                             defaultHeaders: apiRest.DefaultHeaders);
            var entries = DownloadAllEntries(rootFolder, features.Eligibility.RootPath, contentRest);

            // 5. Try to find all keysets that decrypt (normally there's only one).
            var encryptionKey = Util.ConvertMasterKeyToEncryptionKey(masterKey);
            var keysets = FindAndDecryptAllKeysets(entries, encryptionKey);

            // 6. Try to decrypt all account entries and see what decrypts.
            var accounts = FindAndDecryptAllAccounts(entries, keysets);

            // Done, phew!
            return accounts;
        }

        // Returns the master key on successful enrollment.
        internal static byte[] EnrollNewDevice(ClientInfo clientInfo, IUi ui, IRestTransport transport, RestClient apiRest)
        {
            // To enroll we need to generate a key pair. The public key will be sent to the server.
            // These keys don't need to persist since we don't do anything else but enrolling the device with them.
            // We can throw them away after we're done.
            var (publicKey, privateKey) = CryptoBoxKeypair();

            // 1. Initial enrollment request which sends the notification to other devices to prompt the user to approve
            var enrollInfo = Post<R.EnrollDevice>("passwords/enroll_device",
                                                    new Dictionary<string, object>
                                                    {
                                                        ["device_id"] = clientInfo.DeviceId,
                                                        ["device_public_key"] = publicKey.ToBase64(),
                                                        ["client_ts_ms_utc"] = Os.UnixSeconds(),
                                                        ["app_version"] = "3.23.1",
                                                        ["platform"] = "chrome",
                                                        ["platform_version"] = "Chrome 115.0.0.0",
                                                        ["device_name"] = clientInfo.DeviceName,
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

            if (enrollInfo.Status.Tag != "device_requested")
                throw new InternalErrorException(
                    MakeErrorMessage($"expected status 'device_requested', got '{enrollInfo.Status.Tag}'"));

            var deviceNames = enrollInfo.Status.DeviceRequested
                .Select(x => x.Name.IsNullOrEmpty() ? "Unknown" : x.Name)
                .ToArray();

            ui.EnrollRequestSent(deviceNames);

            // 2. Get Bolt credentials that are used to subscribe to a Bolt channel to receive the master key
            var boltInfo = Post<R.BoltInfo>("passwords/get_bolt_info",
                                            new Dictionary<string, object>
                                            {
                                                ["device_id"] = clientInfo.DeviceId,
                                            },
                                            RestClient.NoHeaders,
                                            apiRest);

            var thunderRest = new RestClient(transport,
                                             "https://thunder.dropbox.com/2",
                                             defaultHeaders: apiRest.DefaultHeaders);

            // 3. Subscribe to a Bolt channel to receive the encrypted master key
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
                throw new InternalErrorException(MakeErrorMessage("invalid response format"));

            var messageType = payload.IntAt("message_type", -1);
            switch (messageType)
            {
            case 1: // Accepted
                break;

            case 3: // Denied
                throw new BadMultiFactorException(MakeErrorMessage("enrollment request was denied"));

            default:
                throw new InternalErrorException(MakeErrorMessage($"unknown message type {messageType}"));
            }

            var sourceDevicePublicKey = payload.StringAt("source_device_public_key", null);
            var encryptedData = payload.SelectToken("encrypted_user_key_bundle.encrypted_data")?.ToString();
            var nonce = payload.SelectToken("encrypted_user_key_bundle.nonce")?.ToString();

            if (sourceDevicePublicKey == null || encryptedData == null || nonce == null)
                throw new InternalErrorException(MakeErrorMessage("invalid public/master key format"));

            // Decrypt the master key
            return CryptoBoxOpenEasy(encryptedData.Decode64(),
                                     nonce.Decode64(),
                                     privateKey,
                                     sourceDevicePublicKey.Decode64());

            static string MakeErrorMessage(string message) => $"Failed to enroll the device: {message}";
        }

        internal static string AcquireOAuthToken(IUi ui, IRestTransport transport)
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
            var code = Url.ExtractQueryParameter(redirectUrl, "code");
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

        // App info
        internal const string ClientId = "8ho1d12ibryh3ez";

        // Storage keys
        internal const string OAuthTokenKey = "oauth-token";
        internal const string MasterKeyKey = "master-key";

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

        internal static R.EncryptedEntry[] DownloadAllEntries(R.RootFolder rootFolder,
                                                              string rootPath,
                                                              RestClient contentRest)
        {
            return rootFolder.Entries
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

        internal static (byte[] PublicKey, byte[] PrivateKey) CryptoBoxKeypair()
        {
            Curve25519XSalsa20Poly1305.KeyPair(out var privateKey, out var publicKey);
            if (publicKey.Length != PublicKeySize || privateKey.Length != PrivateKeySize)
                throw new InternalErrorException("Invalid key length");

            return (publicKey, privateKey);
        }

        internal static byte[] CryptoBoxOpenEasy(byte[] ciphertext,
                                                 byte[] nonce,
                                                 byte[] ourPrivateKey,
                                                 byte[] theirPublicKey)
        {
            var plain = new byte[ciphertext.Length - XSalsa20Poly1305.TagLength];
            if (new Curve25519XSalsa20Poly1305(ourPrivateKey, theirPublicKey).TryDecrypt(plain, ciphertext, nonce))
                return plain;

            throw new CryptoException("Failed to decrypt");
        }

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

        //
        // JSON
        //

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
                var error = JsonConvert.DeserializeObject<Response.Error>(response.Content ?? "");
                if (error?.Status.Tag == "invalid_access_token")
                    throw new TokenExpiredException();
            }
            catch (JsonException)
            {
                // Ignore the failed attempt to deserialize the error response and return a generic error below
            }

            return MakeError($"POST request to {response.RequestUri} failed", response.Error);
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
