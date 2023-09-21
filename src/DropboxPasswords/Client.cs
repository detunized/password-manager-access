// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
// TODO: This library implement exactly what we need but it has a somewhat incompatible license.
//       See if we could repurpose NaCl.Core which is MIT licensed to do what we need.
//       It doesn't provide the crypto_box_open_easy equivalent by default.
#if USE_NACL
using NaCl;
#endif
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
            var oauthToken = storage.LoadString(OAuthTokenKey);
            if (oauthToken.IsNullOrEmpty())
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

                oauthToken = response.Data.AccessToken;
                storage.StoreString(OAuthTokenKey, oauthToken);
            }

            // Normally we would use the master key to decrypt the vault. In case we don't have it, we need to enroll
            // a new device and receive the key form one of the devices enrolled previously. To do that we send the
            // public key to the server which passes it along to one of the devices. The device encrypts the master key
            // end sends it back to us.
            var masterKey = LoadMasterKey(storage);
            if (masterKey == null)
            {
                // To enroll we need to generate a key pair. The public key will be sent to the server.
                // These keys don't need to persist since we don't do anything else but enrolling the device with them.
                // We can throw them away after we're done.
                var (publicKey, privateKey) = CryptoBoxKeypair();

                // publicKey = "TCbJZg07erD5JLdngqn0leqaTv4yDPaPciZ4/IlgqUM=".Decode64();
                // privateKey = "EDrBprqwud8YbZ10T0/7JmDcQY1tKWDmUFNqV8bw5k0=".Decode64();

                // A working example of crypto_box_open_easy from the original JS source:
                // gA(
                //     {
                //         encrypted: Si.fromBase64("kDZmVHrS3ZRNZUnUcaKQ6z5KqR5XYY6ymmJLAZhNVJk=").data.val, // encrypted key
                //         nonce: Si.fromBase64("nSgGUq0+wgk6FuTonn/gLX3tMRYyDEsP").data.val                  // nonce
                //     },
                //     Si.fromBase64("EDrBprqwud8YbZ10T0/7JmDcQY1tKWDmUFNqV8bw5k0=").data.val,                // out private key
                //     Si.fromBase64("1YPKexhpTXpqx9WQC2rfQ19qg1SD27jKkv8Iu2CqZU4=").data.val
                // )

                // CryptoBoxOpenEasy(ciphertext: "kDZmVHrS3ZRNZUnUcaKQ6z5KqR5XYY6ymmJLAZhNVJk=".Decode64(),
                //                   nonce: "nSgGUq0+wgk6FuTonn/gLX3tMRYyDEsP".Decode64(),
                //                   ourPrivateKey: "EDrBprqwud8YbZ10T0/7JmDcQY1tKWDmUFNqV8bw5k0=".Decode64(),
                //                   theirPublicKey: "1YPKexhpTXpqx9WQC2rfQ19qg1SD27jKkv8Iu2CqZU4=".Decode64());

                /*
                {
                    "encryptedBundle": {
                        "base64EncryptedData": "YqvCKDWnmyzM1GhQQIeL91syNpzCK7poC5w610vv1Qsdq1Tjnr169ElXE0IXhQqFD6t9M+xnzdEefAzkPO+q1qb5iadkdoapWYTsjlrHJsDi+B5J3gUa+Pswo8TjTb4UTWqlydPl2SlyOSexEb1tZ/ZZxbKWzJ7HXT8ClrzbBnDR0XUnMuy0/qhKgqfPCSl8AmPdRZ9Jgho2RSou1dR/93QucIFrH6QVQMcck76EQTNfzf2ha59ViTOxnAcwNKyUEsa1wc81Q9uaWRzSVpsGsU+9yQp6nQBsqvU6UySV7G6M9OR+PBxcfTAHK3VFWG0UHoysCSdOXG8pqU+4aOc\u003d",
                        "base64Nonce": "bfs71uSzIiXkYN/5nGs5TmdMU34JHAPB"
                    },
                    "type": "keyset",
                    "version": 1,
                    "identifier": "39B0B629-9D00-4C10-AF7D-62CD0D7383B9"
                }
                */

                // 1. Create the API client
                var apiRest = new RestClient(transport,
                                             "https://api.dropboxapi.com/2",
                                             defaultHeaders: new Dictionary<string, string>
                                             {
                                                 ["Authorization"] = $"Bearer {oauthToken}",
                                                 ["Origin"] = "chrome-extension://bmhejbnmpamgfnomlahkonpanlkcfabg",
                                             });

                // 2. Features
                var features = Post<R.Features>("passwords/get_features_v2",
                                                RestClient.JsonNull, // Important to send null!
                                                RestClient.NoHeaders,
                                                apiRest);

                // 3. Get account info
                var accountInfo = Post<R.AccountInfo>("users/get_current_account",
                                                      RestClient.JsonNull, // Important to send null!
                                                      RestClient.NoHeaders,
                                                      apiRest);

                // 4. Enroll the device
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

                // 5. Get Bolt credentials
                var boltInfo = Post<R.BoltInfo>("passwords/get_bolt_info",
                                                new Dictionary<string, object>
                                                {
                                                    ["device_id"] = deviceId,
                                                },
                                                RestClient.NoHeaders,
                                                apiRest);

                // 6. Subscribe to a Bolt channel to receive the public key
                var thunderRest = new RestClient(transport,
                                                 "https://thunder.dropbox.com/2",
                                                 defaultHeaders: apiRest.DefaultHeaders);

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

                if (keys.SelectToken("$.channel_payloads[0].payloads[0].payload") is var payload && payload != null)
                {
                    var sourceDevicePublicKey = payload.StringAt("source_device_public_key", null);
                    var encryptedData = payload.SelectToken("encrypted_user_key_bundle.encrypted_data")?.ToString();
                    var nonce = payload.SelectToken("encrypted_user_key_bundle.nonce")?.ToString();

                    if (sourceDevicePublicKey == null || encryptedData == null || nonce == null)
                        throw new InternalErrorException("Failed to extract the public key and the encrypted master key");

                    masterKey = CryptoBoxOpenEasy(encryptedData.Decode64(),
                                                  nonce.Decode64(),
                                                  privateKey,
                                                  sourceDevicePublicKey.Decode64());
                    storage.StoreString(MasterKeyKey, masterKey.ToBase64());
                }

                var contentRest = new RestClient(transport,
                                                 "https://content.dropboxapi.com/2",
                                                 defaultHeaders: apiRest.DefaultHeaders);

                var keysetResponse = contentRest.PostRaw("passwords/download",
                                                         "",
                                                         MakePathHeaders($"/{enrollStatus.ActiveKeysetName}.json",
                                                                         features.Eligibility.RootPath));
                if (!keysetResponse.IsSuccessful)
                    throw new InternalErrorException("Failed to download the master keyset");

                Console.WriteLine("Public key: {0}", publicKey.ToBase64());
                Console.WriteLine("Private key: {0}", privateKey.ToBase64());
                Console.WriteLine("Master keyset: {0}", keysetResponse.Content);

                Console.WriteLine("Public key: {0}", publicKey.ToBase64());
            }

            return Array.Empty<Account>();
        }

        internal static byte[]? LoadMasterKey(ISecureStorage storage)
        {
            var masterKeyString = storage.LoadString(MasterKeyKey) ?? "";
            var masterKey = masterKeyString.Decode64();
            if (masterKey.Length != MasterKeySize)
                return null;
            return masterKey;
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
#if USE_NACL
            Curve25519XSalsa20Poly1305.KeyPair(out var privateKey, out var publicKey);
#else
            var privateKey = new byte[PrivateKeySize];
            var publicKey = new byte[PublicKeySize];
#endif
            if (publicKey.Length != PublicKeySize || privateKey.Length != PrivateKeySize)
                throw new InternalErrorException("Invalid key length");

            return (publicKey, privateKey);
        }

        public static byte[] CryptoBoxOpenEasy(byte[] ciphertext, byte[] nonce, byte[] ourPrivateKey, byte[] theirPublicKey)
        {
#if USE_NACL
            var plain = new byte[ciphertext.Length - XSalsa20Poly1305.TagLength];
            if (new Curve25519XSalsa20Poly1305(ourPrivateKey, theirPublicKey).TryDecrypt(plain, ciphertext, nonce))
                return plain;
#endif
            throw new InternalErrorException("Failed to decrypt");
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

        internal const int PublicKeySize = 32;
        internal const int PrivateKeySize = 32;
        internal const int MasterKeySize = 32;

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

        internal static InternalErrorException MakeError(RestResponse response)
        {
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
