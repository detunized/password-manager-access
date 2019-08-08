// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    internal static class Client
    {
        public static Account[] OpenVault(string username,
                                          string password,
                                          string deviceId,
                                          string baseUrl,
                                          Ui ui,
                                          ISecureStorage storage,
                                          IRestTransport transport,
                                          IHttpClient http) // TODO: Port Duo to RestClient and get rid of HttpClient
        {
            // Reset to default. Let the user simply pass a null or "" and not bother with an overload.
            if (baseUrl.IsNullOrEmpty())
                baseUrl = DefaultBaseUrl;

            var rest = new RestClient(transport, baseUrl);

            // 1. Request the number of KDF iterations needed to derive the key
            var iterations = RequestKdfIterationCount(username, rest);

            // 2. Derive the master encryption key or KEK (key encryption key)
            var key = Crypto.DeriveKey(username, password, iterations);

            // 3. Hash the password that is going to be sent to the server
            var hash = Crypto.HashPassword(password, key);

            // 4. Authenticate with the server and get the token
            var token = Login(username, hash, deviceId, ui, storage, rest, http);

            // 5. Fetch the vault
            var encryptedVault = DownloadVault(rest, token);

            // 6. Decrypt and parse the vault. Done!
            return DecryptVault(encryptedVault, key);
        }

        //
        // Internal
        //

        internal static int RequestKdfIterationCount(string username, RestClient rest)
        {
            var info = RequestKdfInfo(username, rest);
            if (info.Kdf != Response.KdfMethod.Pbkdf2Sha256)
                throw new UnsupportedFeatureException($"KDF method {info.Kdf} is not supported");

            return info.KdfIterations;
        }

        internal static Response.KdfInfo RequestKdfInfo(string username, RestClient rest)
        {
            var response = rest.PostJson<Response.KdfInfo>("api/accounts/prelogin",
                                                           new Dictionary<string, object> {{"email", username}});
            if (response.IsSuccessful)
                return response.Data;

            // Special case: when the HTTP status is 4XX we should fall back to the default settings
            if (IsHttp4XX(response))
                return DefaultKdfInfo;

            throw MakeSpecializedError(response);
        }

        internal static string Login(string username,
                                     byte[] passwordHash,
                                     string deviceId,
                                     Ui ui,
                                     ISecureStorage storage,
                                     RestClient rest,
                                     IHttpClient http)
        {
            // Try simple password login, potentially with a stored second factor token if
            // "remember me" was used before.
            var rememberMeOptions = GetRememberMeOptions(storage);
            var response = RequestAuthToken(username, passwordHash, deviceId, rememberMeOptions, rest);

            // Simple password login (no 2FA) succeeded
            if (response.AuthToken != null)
                return response.AuthToken;

            var secondFactor = response.SecondFactor;
            if (secondFactor.Methods == null || secondFactor.Methods.Count == 0)
                throw new InternalErrorException("Expected a non empty list of available 2FA methods");

            // We had a "remember me" token saved, but the login failed anyway. This token is not valid anymore.
            if (rememberMeOptions != null)
                EraseRememberMeToken(storage);

            var method = ChooseSecondFactorMethod(secondFactor, ui);
            var extra = secondFactor.Methods[method];
            Ui.Passcode passcode;
            switch (method)
            {
            case Response.SecondFactorMethod.GoogleAuth:
                passcode = ui.ProvideGoogleAuthPasscode();
                break;
            case Response.SecondFactorMethod.Email:
                // When only the email 2FA present, the email is sent by the server right away.
                // Trigger only when other methods are present.
                if (secondFactor.Methods.Count != 1)
                    TriggerEmailMfaPasscode(username, passwordHash, rest);

                passcode = ui.ProvideEmailPasscode((string)extra["Email"] ?? "");
                break;
            case Response.SecondFactorMethod.Duo:
                passcode = Duo.Authenticate((string)extra["Host"] ?? "",
                                            (string)extra["Signature"] ?? "",
                                            ui,
                                            http); // TODO: Port to RestClient
                break;
            case Response.SecondFactorMethod.YubiKey:
                passcode = ui.ProvideYubiKeyPasscode();
                break;
            default:
                throw new UnsupportedFeatureException($"2FA method {method} is not supported");
            }

            // We're done interacting with the UI
            ui.Close();

            if (passcode == null)
                throw new CanceledMultiFactorException("Second factor step is canceled by the user");

            var secondFactorResponse = RequestAuthToken(username,
                                                        passwordHash,
                                                        deviceId,
                                                        new SecondFactorOptions(method,
                                                                                passcode.Code,
                                                                                passcode.RememberMe),
                                                        rest);

            // Password + 2FA is successful
            if (secondFactorResponse.AuthToken != null)
            {
                SaveRememberMeToken(secondFactorResponse, storage);
                return secondFactorResponse.AuthToken;
            }

            throw new BadMultiFactorException("Second factor code is not correct");
        }

        internal static SecondFactorOptions GetRememberMeOptions(ISecureStorage storage)
        {
            var storedRememberMeToken = storage.LoadString(RememberMeTokenKey);
            if (storedRememberMeToken.IsNullOrEmpty())
                return null;

            return new SecondFactorOptions(Response.SecondFactorMethod.RememberMe, storedRememberMeToken, false);
        }

        internal static void SaveRememberMeToken(TokenOrSecondFactor reseponse, ISecureStorage storage)
        {
            var token = reseponse.RememberMeToken;
            if (token != null)
                storage.StoreString(RememberMeTokenKey, token);
        }

        internal static void EraseRememberMeToken(ISecureStorage storage)
        {
            storage.StoreString(RememberMeTokenKey, "");
        }

        internal static Response.SecondFactorMethod ChooseSecondFactorMethod(Response.SecondFactor secondFactor, Ui ui)
        {
            var methods = secondFactor.Methods;
            if (methods == null || methods.Count == 0)
                throw new InternalErrorException("Logical error: should be called with non empty list of methods");

            if (methods.Count == 1)
                return methods.ElementAt(0).Key;

            var availableMethods = new List<Ui.MfaMethod>();
            availableMethods.Add(Ui.MfaMethod.Cancel);

            foreach (var m in methods.Keys)
            {
                switch (m)
                {
                case Response.SecondFactorMethod.GoogleAuth:
                    availableMethods.Add(Ui.MfaMethod.GoogleAuth);
                    break;
                case Response.SecondFactorMethod.Email:
                    availableMethods.Add(Ui.MfaMethod.Email);
                    break;
                case Response.SecondFactorMethod.Duo:
                    availableMethods.Add(Ui.MfaMethod.Duo);
                    break;
                case Response.SecondFactorMethod.YubiKey:
                    availableMethods.Add(Ui.MfaMethod.YubiKey);
                    break;
                case Response.SecondFactorMethod.RememberMe:
                    break;
                default:
                    throw new UnsupportedFeatureException("TODO");
                }
            }

            switch (ui.ChooseMfaMethod(availableMethods.ToArray()))
            {
            case Ui.MfaMethod.Cancel:
                throw new CanceledMultiFactorException("TODO");
            case Ui.MfaMethod.GoogleAuth:
                return Response.SecondFactorMethod.GoogleAuth;
            case Ui.MfaMethod.Email:
                return Response.SecondFactorMethod.Email;
            case Ui.MfaMethod.Duo:
                return Response.SecondFactorMethod.Duo;
            case Ui.MfaMethod.YubiKey:
                return Response.SecondFactorMethod.YubiKey;
            default:
                throw new InternalErrorException("TODO");
            }
        }

        internal struct TokenOrSecondFactor
        {
            public readonly string AuthToken;
            public readonly string RememberMeToken;
            public readonly Response.SecondFactor SecondFactor;

            public TokenOrSecondFactor(string authToken, string rememberMeToken)
            {
                AuthToken = authToken;
                RememberMeToken = rememberMeToken;
                SecondFactor = new Response.SecondFactor();
            }

            public TokenOrSecondFactor(Response.SecondFactor secondFactor)
            {
                AuthToken = null;
                RememberMeToken = null;
                SecondFactor = secondFactor;
            }
        }

        internal class SecondFactorOptions
        {
            public readonly Response.SecondFactorMethod Method;
            public readonly string Passcode;
            public readonly bool RememberMe;

            public SecondFactorOptions(Response.SecondFactorMethod method, string passcode, bool rememberMe)
            {
                Method = method;
                Passcode = passcode;
                RememberMe = rememberMe;
            }
        }

        internal static TokenOrSecondFactor RequestAuthToken(string username,
                                                             byte[] passwordHash,
                                                             string deviceId,
                                                             RestClient rest)
        {
            return RequestAuthToken(username, passwordHash, deviceId, null, rest);
        }

        // secondFactorOptions is optional
        internal static TokenOrSecondFactor RequestAuthToken(string username,
                                                             byte[] passwordHash,
                                                             string deviceId,
                                                             SecondFactorOptions secondFactorOptions,
                                                             RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"username", username},
                {"password", passwordHash.ToBase64()},
                {"grant_type", "password"},
                {"scope", "api offline_access"},
                {"client_id", "web"},
                {"deviceType", "9"},
                {"deviceName", "chrome"},
                {"deviceIdentifier", deviceId},
            };

            if (secondFactorOptions != null)
            {
                parameters["twoFactorProvider"] = secondFactorOptions.Method.ToString("d");
                parameters["twoFactorToken"] = secondFactorOptions.Passcode;
                parameters["twoFactorRemember"] = secondFactorOptions.RememberMe ? "1" : "0";
            }

            var response = rest.PostForm<Response.AuthToken>("identity/connect/token", parameters);
            if (response.IsSuccessful)
            {
                var token = response.Data;
                return new TokenOrSecondFactor($"{token.TokenType} {token.AccessToken}", token.TwoFactorToken);
            }

            // TODO: Write a test for this situation.
            var secondFactor = ExtractSecondFactorFromResponse(response);
            if (secondFactor.HasValue)
                return new TokenOrSecondFactor(secondFactor.Value);

            throw MakeSpecializedError(response);
        }

        internal static Response.SecondFactor? ExtractSecondFactorFromResponse(RestResponse response)
        {
            // In the case of 2FA the server returns some 400+ HTTP error and the response contains
            // extra information about the available 2FA methods.
            if (!IsHttp4XX(response))
                return null;

            // TODO: A refactoring opportunity here. This pattern could be converted to
            //       RestResponse<U> RestResponse<T>.CastTo<U>() { ... }
            try
            {
                return JsonConvert.DeserializeObject<Response.SecondFactor>(response.Content);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        internal static void TriggerEmailMfaPasscode(string username, byte[] passwordHash, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                {"email", username},
                {"masterPasswordHash", passwordHash.ToBase64()},
            };

            var response = rest.PostJson("api/two-factor/send-email-login", parameters);
            if (response.IsSuccessful)
                return;

            throw MakeSpecializedError(response);
        }

        internal static Response.Vault DownloadVault(RestClient rest, string token)
        {
            var response = rest.Get<Response.Vault>("api/sync?excludeDomains=true",
                                                    new Dictionary<string, string> {{"Authorization", token}});
            if (response.IsSuccessful)
                return response.Data;

            throw MakeSpecializedError(response);
        }

        internal static Account[] DecryptVault(Response.Vault vault, byte[] key)
        {
            var vaultKey = DecryptVaultKey(vault.Profile, key);
            var privateKey = DecryptPrivateKey(vault.Profile, vaultKey);
            var orgKeys = DecryptOrganizationKeys(vault.Profile, privateKey);
            var folders = ParseFolders(vault.Folders, vaultKey);

            return vault.Ciphers
                .Where(i => i.Type == Response.ItemType.Login)
                .Select(i => ParseAccountItem(i, vaultKey, orgKeys, folders)).ToArray();
        }

        internal static byte[] DecryptVaultKey(Response.Profile profile, byte[] derivedKey)
        {
            // By default use the derived key, this is true for some old vaults.
            if (profile.Key.IsNullOrEmpty())
                return derivedKey;

            // The newer vaults have a key stored in the profile section. It's encrypted
            // with the derived key, with is effectively a KEK now.
            return DecryptToBytes(profile.Key, derivedKey);
        }

        // Null if not present
        internal static byte[] DecryptPrivateKey(Response.Profile profile, byte[] vaultKey)
        {
            if (profile.PrivateKey.IsNullOrEmpty())
                return null;

            return DecryptToBytes(profile.PrivateKey, vaultKey);
        }

        internal static Dictionary<string, byte[]> DecryptOrganizationKeys(Response.Profile profile, byte[] privateKey)
        {
            if (privateKey == null || profile.Organizations == null)
                return new Dictionary<string, byte[]>();

            return profile.Organizations.ToDictionary(x => x.Id, x => DecryptToBytes(x.Key, privateKey));
        }

        internal static Dictionary<string, string> ParseFolders(Response.Folder[] folders, byte[] key)
        {
            return folders.ToDictionary(i => i.Id, i => DecryptToString(i.Name, key));
        }

        internal static Account ParseAccountItem(Response.Item item,
                                                 byte[] vaultKey,
                                                 Dictionary<string, byte[]> orgKeys,
                                                 Dictionary<string, string> folders)
        {
            var key = item.OrganizationId.IsNullOrEmpty()
                ? vaultKey
                : orgKeys[item.OrganizationId];

            var folder = item.FolderId != null && folders.ContainsKey(item.FolderId)
                ? folders[item.FolderId]
                : "";

            return new Account(id: item.Id,
                               name: DecryptToStringOrBlank(item.Name, key),
                               username: DecryptToStringOrBlank(item.Login.Username, key),
                               password: DecryptToStringOrBlank(item.Login.Password, key),
                               url: DecryptToStringOrBlank(item.Login.Uri, key),
                               note: DecryptToStringOrBlank(item.Notes, key),
                               folder: folder);
        }

        internal static byte[] DecryptToBytes(string s, byte[] key)
        {
            return CipherString.Parse(s).Decrypt(key);
        }

        internal static string DecryptToString(string s, byte[] key)
        {
            return  DecryptToBytes(s, key).ToUtf8();
        }

        // s may be null
        internal static string DecryptToStringOrBlank(string s, byte[] key)
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

        internal static BaseException MakeSpecializedError(RestResponse response)
        {
            if (response.IsNetworkError)
                return new NetworkErrorException("Network error has occured", response.Error);

            if (response.HasError)
                return new InternalErrorException("Network request or response parsing failed", response.Error);

            if (!IsHttp4XX(response))
                return new InternalErrorException($"Unexpected response from the server ({response.StatusCode})");

            var message = GetServerErrorMessage(response);
            if (message.IsNullOrEmpty())
                return new InternalErrorException("Unexpected response from the server");

            if (message.Contains("Username or password is incorrect"))
                return new BadCredentialsException(message);

            if (message.Contains("Two-step token is invalid"))
                return new BadMultiFactorException(message);

            return new InternalErrorException($"Server responded with an error: '{message}'");
        }

        internal static string GetServerErrorMessage(RestResponse response)
        {
            try
            {
                var parsed = JObject.Parse(response.Content ?? "{}");
                return (string)(parsed["ErrorModel"] ?? parsed)["Message"];
            }
            catch (JsonException)
            {
                return null;
            }
        }

        //
        // Private
        //

        private const string DefaultBaseUrl = "https://vault.bitwarden.com";
        private const string RememberMeTokenKey = "remember-me-token";

        private static readonly Response.KdfInfo DefaultKdfInfo = new Response.KdfInfo
        {
            Kdf = Response.KdfMethod.Pbkdf2Sha256,
            KdfIterations = 5000
        };
    }
}
