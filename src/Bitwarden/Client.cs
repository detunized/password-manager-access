// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using U2fWin10;
using R = PasswordManagerAccess.Bitwarden.Response;

namespace PasswordManagerAccess.Bitwarden
{
    public static class Client
    {
        // Use this function to generate a random device ID. The device ID should be unique to each
        // installation, but it should not be new on every run. A new random device ID should be
        // generated with GenerateRandomDeviceId on the first run and reused later on.
        public static string GenerateRandomDeviceId() => Guid.NewGuid().ToString();

        //
        // Single shot methods
        //

        // The main entry point for a single shot method. Use this function to open the vault
        // in the browser mode. In this case the login process is interactive when 2FA is enabled.
        // This is an old mode that might potentially trigger a captcha. Captcha solving is not
        // supported. There's no way to complete a login and get the vault if the captcha is triggered.
        // Use the CLI/API mode. This mode requires a different type of credentials.
        public static Vault Open(ClientInfoBrowser clientInfo, IUi ui, ISecureStorage storage) => Open(clientInfo, null, ui, storage);

        // This version allows a custom base URL. `baseUrl` could be set to null or "" for the default value.
        public static Vault Open(ClientInfoBrowser clientInfo, string baseUrl, IUi ui, ISecureStorage storage) =>
            DownloadAndLogOut(LogIn(clientInfo, baseUrl, ui, storage));

        // The main entry point for a single shot method. Use this function to open the vault in the
        // CLI/API mode. In this mode the login is fully non-interactive even with 2FA enabled. Bitwarden
        // servers don't use 2FA in this mode and permit to bypass it. There's no captcha in this mode
        // either. This is the preferred mode. This mode requires a different type of credentials that
        // could be found in the vault settings: the client ID and the client secret.
        public static Vault Open(ClientInfoCliApi clientInfo, string baseUrl = null) => DownloadAndLogOut(LogIn(clientInfo, baseUrl));

        //
        // LogIn, DownloadVault, LogOut sequence
        //

        // This method performs a login in the browser mode. The returned session can be used to
        // download the vault, if needed multiple times. When no longer needed LogOut should be called.
        // See signle shot Open for more comments.
        public static Session LogIn(ClientInfoBrowser clientInfo, IUi ui, ISecureStorage storage) => LogIn(clientInfo, null, ui, storage);

        // Same as above but allows a custom base URL. `baseUrl` could be set to null or "" for the default value.
        public static Session LogIn(ClientInfoBrowser clientInfo, string baseUrl, IUi ui, ISecureStorage storage)
        {
            var transport = new RestTransport();
            try
            {
                return LogInBrowser(clientInfo, baseUrl, ui, storage, transport);
            }
            catch (Exception)
            {
                transport.Dispose();
                throw;
            }
        }

        // This method performs a login in the CLI/API mode. The returned session can be used to
        // download the vault, if needed multiple times. When no longer needed LogOut should be called.
        // See single shot Open for more comments.
        public static Session LogIn(ClientInfoCliApi clientInfo, string baseUrl = null)
        {
            var transport = new RestTransport();
            try
            {
                return LogInCliApi(clientInfo, baseUrl, transport);
            }
            catch (Exception)
            {
                transport.Dispose();
                throw;
            }
        }

        // This method downloads the vault from the server. The session must be obtained from LogIn.
        public static Vault DownloadVault(Session session)
        {
            var encryptedVault = FetchVault(session);
            var (accounts, sshKeys, collections, organizations, errors) = DecryptVault(encryptedVault, session.Key);

            return new Vault
            {
                Accounts = accounts,
                SshKeys = sshKeys,
                Collections = collections,
                Organizations = organizations,
                ParseErrors = errors,
            };
        }

        // This method logs out the session. Call this when the session is no longer needed.
        // After that the session object could not be used anymore. The behavior is undefined
        // if it's used again.
        public static void LogOut(Session session)
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
        }

        //
        // Internal
        //

        internal static Vault DownloadAndLogOut(Session session)
        {
            try
            {
                return DownloadVault(session);
            }
            finally
            {
                LogOut(session);
            }
        }

        internal static Session LogInBrowser(ClientInfoBrowser clientInfo, string baseUrl, IUi ui, ISecureStorage storage, IRestTransport transport)
        {
            var rest = MakeRestClients(baseUrl, transport);

            // 1. Request the number of KDF iterations needed to derive the key
            var kdfInfo = RequestKdfInfo(clientInfo.Username, rest.Api);

            // 2. Derive the master encryption key or KEK (key encryption key)
            var key = Util.DeriveKey(clientInfo.Username, clientInfo.Password, kdfInfo);

            // 3. Hash the password that is going to be sent to the server
            var hash = Util.HashPassword(clientInfo.Password, key);

            // 4. Authenticate with the server and get the token
            var token = Login(clientInfo.Username, hash, clientInfo.DeviceId, ui, storage, rest.Api, rest.Identity);

            return new Session(token, key, rest.Api, transport);
        }

        internal static Session LogInCliApi(ClientInfoCliApi clientInfo, string baseUrl, IRestTransport transport)
        {
            var rest = MakeRestClients(baseUrl, transport);

            // 1. Login and get the client info
            var (token, kdfInfo) = LogInCliApi(clientInfo.ClientId, clientInfo.ClientSecret, clientInfo.DeviceId, rest.Identity);

            // 2. Fetch the profile to get the email for key derivation
            var profile = FetchProfile(token, rest.Api);

            // 3. Derive the master encryption key or KEK (key encryption key)
            var key = Util.DeriveKey(profile.Email, clientInfo.Password, kdfInfo);

            return new Session(token, key, rest.Api, transport);
        }

        internal static (RestClient Api, RestClient Identity) MakeRestClients(string baseUrl, IRestTransport transport)
        {
            var apiUrl = DefaultApiUrl;
            var identityUrl = DefaultIdentityUrl;

            // When the base URL is specified we're targeting a self-hosted installation.
            // In this case the `api.` and `identity.` subdomains are not used.
            if (!baseUrl.IsNullOrEmpty())
            {
                var baseUrlNoSlash = baseUrl.TrimEnd('/');
                apiUrl = baseUrlNoSlash + "/api";
                identityUrl = baseUrlNoSlash + "/identity";
            }

            return (
                Api: new RestClient(transport, apiUrl, defaultHeaders: DefaultRestHeaders),
                Identity: new RestClient(transport, identityUrl, defaultHeaders: DefaultRestHeaders)
            );
        }

        internal static R.KdfInfo RequestKdfInfo(string username, RestClient rest)
        {
            var response = rest.PostJson<R.KdfInfo>("accounts/prelogin", new Dictionary<string, object> { { "email", username } });

            if (response.IsSuccessful)
            {
                var kdfInfo = response.Data;
                ValidateKdfInfo(kdfInfo);

                return kdfInfo;
            }

            // Special case: when the HTTP status is 4XX we should fall back to the default settings
            if (IsHttp4XX(response))
                return DefaultKdfInfo;

            throw MakeSpecializedError(response);
        }

        internal static void ValidateKdfInfo(R.KdfInfo info)
        {
            switch (info.Kdf)
            {
                case R.KdfMethod.Pbkdf2Sha256:
                    if (info.Iterations <= 0)
                        throw new InternalErrorException($"Invalid iteration count: {info.Iterations}");
                    break;
                case R.KdfMethod.Argon2id:
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

        internal static string Login(
            string username,
            byte[] passwordHash,
            string deviceId,
            IUi ui,
            ISecureStorage storage,
            RestClient apiRest,
            RestClient identityRest
        )
        {
            // Try simple password login, potentially with a stored second factor token if
            // "remember me" was used before.
            var rememberMeOptions = GetRememberMeOptions(storage);
            var response = RequestAuthToken(username, passwordHash, deviceId, rememberMeOptions, identityRest);

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
            Passcode passcode = null;

            switch (method)
            {
                case R.SecondFactorMethod.GoogleAuth:
                    passcode = ui.ProvideGoogleAuthPasscode();
                    break;
                case R.SecondFactorMethod.Email:
                    // When only the email 2FA present, the email is sent by the server right away.
                    // Trigger only when other methods are present.
                    if (secondFactor.Methods.Count != 1)
                        TriggerEmailMfaPasscode(username, passwordHash, apiRest);

                    passcode = ui.ProvideEmailPasscode((string)extra["Email"] ?? "");
                    break;
                case R.SecondFactorMethod.Duo:
                case R.SecondFactorMethod.DuoOrg:
                {
                    // TODO: The logic here is a bit brittle. Remove it once Duo V1 is finally removed in October 2024.

                    // It's a bit messy here. Normally when AuthUrl is present that means we should use V4.
                    // The problem with V4 that it could redirect to the traditional prompt with is handled by V1.
                    // So we try V4 first and if it redirects to V1 we try V1.
                    var needV1 = !extra.ContainsKey("AuthUrl");

                    if (!needV1)
                    {
                        var v4 = DuoV4.Authenticate((string)extra["AuthUrl"], ui, apiRest.Transport);

                        if (v4 == DuoResult.RedirectToV1)
                            needV1 = true; // Fallback to V1 below
                        else if (v4 != null)
                            passcode = new Passcode($"{v4.Code}|{v4.State}", v4.RememberMe);
                    }

                    if (needV1)
                    {
                        var v1 = DuoV1.Authenticate((string)extra["Host"] ?? "", (string)extra["Signature"] ?? "", ui, apiRest.Transport);
                        if (v1 != null)
                            passcode = new Passcode(v1.Code, v1.RememberMe);
                    }

                    break;
                }
                case R.SecondFactorMethod.YubiKey:
                    passcode = ui.ProvideYubiKeyPasscode();
                    break;
                case R.SecondFactorMethod.U2f:
                    passcode = AskU2fPasscode(JObject.Parse((string)extra["Challenge"]), ui);
                    break;
                default:
                    throw new UnsupportedFeatureException($"2FA method {method} is not supported");
            }

            // We're done interacting with the UI
            ui.Close();

            if (passcode == null)
                throw MakeCancelledMfaError();

            var secondFactorResponse = RequestAuthToken(
                username,
                passwordHash,
                deviceId,
                new SecondFactorOptions(method, passcode.Code, passcode.RememberMe),
                identityRest
            );

            // Password + 2FA is successful
            if (secondFactorResponse.AuthToken != null)
            {
                SaveRememberMeToken(secondFactorResponse, storage);
                return secondFactorResponse.AuthToken;
            }

            throw new BadMultiFactorException("Second factor code is not correct");
        }

        internal static (string Token, R.KdfInfo KdfInfo) LogInCliApi(string clientId, string clientSecret, string deviceId, RestClient rest)
        {
            var parameters = new Dictionary<string, object>
            {
                { "client_id", clientId },
                { "client_secret", clientSecret },
                { "grant_type", "client_credentials" },
                { "scope", "api" },
                { "deviceType", DeviceType },
                { "deviceName", Platform },
                { "deviceIdentifier", deviceId },
            };

            var response = rest.PostForm<R.TokenCliApi>("connect/token", parameters);
            if (!response.IsSuccessful)
                throw MakeSpecializedError(response);

            var authInfo = response.Data;
            var kdfInfo = new R.KdfInfo
            {
                Kdf = authInfo.Kdf,
                Iterations = authInfo.KdfIterations,
                Memory = authInfo.Memory,
                Parallelism = authInfo.Parallelism,
            };
            ValidateKdfInfo(kdfInfo);

            return ($"{authInfo.TokenType} {authInfo.AccessToken}", kdfInfo);
        }

        internal static SecondFactorOptions GetRememberMeOptions(ISecureStorage storage)
        {
            var storedRememberMeToken = storage.LoadString(RememberMeTokenKey);
            if (storedRememberMeToken.IsNullOrEmpty())
                return null;

            return new SecondFactorOptions(R.SecondFactorMethod.RememberMe, storedRememberMeToken, false);
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

        internal static Passcode AskU2fPasscode(JObject u2fParams, IUi ui)
        {
            var appId = (string)u2fParams["appId"];
            var challenge = (string)u2fParams["challenge"];
            var keyHandle = (string)u2fParams["keys"][0]["keyHandle"]; // TODO: Support multiple keys

            U2f.Assertion assertion;
            try
            {
                assertion = U2f.GetAssertion(appId, challenge, "https://vault.bitwarden.com", keyHandle);
            }
            catch (U2fWin10.CanceledException e)
            {
                throw MakeCancelledMfaError(e);
            }
            catch (U2fWin10.ErrorException e)
            {
                throw MakeFailedMfaError(e);
            }

            // This is the 2FA token that is expected by the BW server
            var token = JsonConvert.SerializeObject(
                new
                {
                    keyHandle = assertion.KeyHandle,
                    clientData = assertion.ClientData,
                    signatureData = assertion.Signature,
                }
            );

            // TODO: Add support for remember-me.
            return new Passcode(token, false);
        }

        internal static R.SecondFactorMethod ChooseSecondFactorMethod(R.SecondFactor secondFactor, IUi ui)
        {
            var methods = secondFactor.Methods;
            if (methods == null || methods.Count == 0)
                throw new InternalErrorException("Logical error: should be called with non empty list of methods");

            var availableMethods = new List<Ui.MfaMethod>();
            foreach (var m in methods.Keys)
            {
                switch (m)
                {
                    case R.SecondFactorMethod.GoogleAuth:
                        availableMethods.Add(Ui.MfaMethod.GoogleAuth);
                        break;
                    case R.SecondFactorMethod.Email:
                        availableMethods.Add(Ui.MfaMethod.Email);
                        break;
                    case R.SecondFactorMethod.Duo:
                        availableMethods.Add(Ui.MfaMethod.Duo);
                        break;
                    case R.SecondFactorMethod.YubiKey:
                        availableMethods.Add(Ui.MfaMethod.YubiKey);
                        break;
                    case R.SecondFactorMethod.U2f:
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                            availableMethods.Add(Ui.MfaMethod.U2f);
                        break;
                    case R.SecondFactorMethod.RememberMe:
                        break;
                    case R.SecondFactorMethod.DuoOrg:
                        availableMethods.Add(Ui.MfaMethod.DuoOrg);
                        break;
                }
            }

            // Only unsupported methods were found
            if (availableMethods.Count == 0)
            {
                var unsupported = string.Join(", ", methods.Keys);
                throw new UnsupportedFeatureException($"Seconds factor methods [{unsupported}] are not supported");
            }

            // Cancel is always available
            availableMethods.Add(Ui.MfaMethod.Cancel);

            return ui.ChooseMfaMethod(availableMethods.ToArray()) switch
            {
                Ui.MfaMethod.Cancel => throw MakeCancelledMfaError(),
                Ui.MfaMethod.GoogleAuth => R.SecondFactorMethod.GoogleAuth,
                Ui.MfaMethod.Email => R.SecondFactorMethod.Email,
                Ui.MfaMethod.Duo => R.SecondFactorMethod.Duo,
                Ui.MfaMethod.YubiKey => R.SecondFactorMethod.YubiKey,
                Ui.MfaMethod.U2f => R.SecondFactorMethod.U2f,
                Ui.MfaMethod.DuoOrg => R.SecondFactorMethod.DuoOrg,
                _ => throw new InternalErrorException("The user responded with invalid input"),
            };
        }

        internal struct TokenOrSecondFactor
        {
            public readonly string AuthToken;
            public readonly string RememberMeToken;
            public readonly R.SecondFactor SecondFactor;

            public TokenOrSecondFactor(string authToken, string rememberMeToken)
            {
                AuthToken = authToken;
                RememberMeToken = rememberMeToken;
                SecondFactor = new R.SecondFactor();
            }

            public TokenOrSecondFactor(R.SecondFactor secondFactor)
            {
                AuthToken = null;
                RememberMeToken = null;
                SecondFactor = secondFactor;
            }
        }

        internal class SecondFactorOptions
        {
            public readonly R.SecondFactorMethod Method;
            public readonly string Passcode;
            public readonly bool RememberMe;

            public SecondFactorOptions(R.SecondFactorMethod method, string passcode, bool rememberMe)
            {
                Method = method;
                Passcode = passcode;
                RememberMe = rememberMe;
            }
        }

        internal static TokenOrSecondFactor RequestAuthToken(string username, byte[] passwordHash, string deviceId, RestClient rest)
        {
            return RequestAuthToken(username, passwordHash, deviceId, null, rest);
        }

        // secondFactorOptions is optional
        internal static TokenOrSecondFactor RequestAuthToken(
            string username,
            byte[] passwordHash,
            string deviceId,
            SecondFactorOptions secondFactorOptions,
            RestClient rest
        )
        {
            var parameters = new Dictionary<string, object>
            {
                { "username", username },
                { "password", passwordHash.ToBase64() },
                { "grant_type", "password" },
                { "scope", "api offline_access" },
                { "client_id", "cli" },
                { "deviceType", DeviceType },
                { "deviceName", Platform },
                { "deviceIdentifier", deviceId },
            };

            if (secondFactorOptions != null)
            {
                parameters["twoFactorProvider"] = secondFactorOptions.Method.ToString("d");
                parameters["twoFactorToken"] = secondFactorOptions.Passcode;
                parameters["twoFactorRemember"] = secondFactorOptions.RememberMe ? "1" : "0";
            }

            var headers = new Dictionary<string, string> { ["Auth-Email"] = username.ToBytes().ToUrlSafeBase64NoPadding() };

            var response = rest.PostForm<R.AuthToken>("connect/token", parameters, headers);
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

        internal static R.SecondFactor? ExtractSecondFactorFromResponse(RestResponse<string> response)
        {
            // In the case of 2FA the server returns some 400+ HTTP error and the response contains
            // extra information about the available 2FA methods.
            if (!IsHttp4XX(response))
                return null;

            // TODO: A refactoring opportunity here. This pattern could be converted to
            //       RestResponse<U> RestResponse<T>.CastTo<U>() { ... }
            try
            {
                return JsonConvert.DeserializeObject<R.SecondFactor>(response.Content);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        internal static void TriggerEmailMfaPasscode(string username, byte[] passwordHash, RestClient rest)
        {
            var parameters = new Dictionary<string, object> { { "email", username }, { "masterPasswordHash", passwordHash.ToBase64() } };

            var response = rest.PostJson("two-factor/send-email-login", parameters);
            if (response.IsSuccessful)
                return;

            throw MakeSpecializedError(response);
        }

        internal static R.Profile FetchProfile(string token, RestClient rest)
        {
            var response = rest.Get<R.Profile>("accounts/profile", new Dictionary<string, string> { { "Authorization", $"{token}" } });
            if (response.IsSuccessful)
                return response.Data;

            throw MakeSpecializedError(response);
        }

        internal static R.Vault FetchVault(Session session) => FetchVault(session.Token, session.Rest);

        internal static R.Vault FetchVault(string token, RestClient rest)
        {
            var response = rest.Get<R.Vault>("sync?excludeDomains=true", new Dictionary<string, string> { { "Authorization", $"{token}" } });
            if (response.IsSuccessful)
                return response.Data;

            throw MakeSpecializedError(response);
        }

        internal static (Account[], SshKey[], Collection[], Organization[], ParseError[]) DecryptVault(R.Vault vault, byte[] key)
        {
            var vaultKey = DecryptVaultKey(vault.Profile, key);
            var privateKey = DecryptPrivateKey(vault.Profile, vaultKey);
            var orgKeys = DecryptOrganizationKeys(vault.Profile, privateKey);
            var folders = ParseFolders(vault.Folders, vaultKey);
            var collections = ParseCollections(vault.Collections, vaultKey, orgKeys);
            var organizations = ParseOrganizations(vault.Profile.Organizations);
            var collectionsById = collections.ToDictionary(x => x.Id);
            var (accounts, sshKeys, errors) = ParseAccounts(vault.Ciphers, vaultKey, orgKeys, folders, collectionsById);

            return (accounts, sshKeys, collections, organizations, errors);
        }

        private static Organization[] ParseOrganizations(R.Organization[] organizations)
        {
            return organizations.Select(x => new Organization(x.Id ?? "", x.Name ?? "")).ToArray();
        }

        internal static byte[] DecryptVaultKey(R.Profile profile, byte[] derivedKey)
        {
            // By default use the derived key, this is true for some old vaults.
            if (profile.Key.IsNullOrEmpty())
                return derivedKey;

            // The newer vaults have a key stored in the profile section. It's encrypted
            // with the derived key, with is effectively a KEK now.
            return DecryptToBytes(profile.Key, derivedKey);
        }

        // Null if not present
        internal static byte[] DecryptPrivateKey(R.Profile profile, byte[] vaultKey)
        {
            if (profile.PrivateKey.IsNullOrEmpty())
                return null;

            return DecryptToBytes(profile.PrivateKey, vaultKey);
        }

        internal static Dictionary<string, byte[]> DecryptOrganizationKeys(R.Profile profile, byte[] privateKey)
        {
            if (privateKey == null || profile.Organizations == null)
                return new Dictionary<string, byte[]>();

            return profile.Organizations.ToDictionary(x => x.Id, x => DecryptRsaToBytes(x.Key, privateKey));
        }

        internal static Dictionary<string, string> ParseFolders(R.Folder[] folders, byte[] key)
        {
            return folders.ToDictionary(i => i.Id, i => DecryptToString(i.Name, key));
        }

        internal static Collection[] ParseCollections(R.Collection[] collections, byte[] vaultKey, Dictionary<string, byte[]> orgKeys)
        {
            return collections
                .Select(x => new Collection(
                    id: x.Id,
                    name: DecryptToString(x.Name, x.OrganizationId.IsNullOrEmpty() ? vaultKey : orgKeys[x.OrganizationId]),
                    organizationId: x.OrganizationId ?? "",
                    hidePasswords: x.HidePasswords
                ))
                .ToArray();
        }

        internal static (Account[], SshKey[], ParseError[]) ParseAccounts(
            R.Item[] items,
            byte[] vaultKey,
            Dictionary<string, byte[]> orgKeys,
            Dictionary<string, string> folders,
            Dictionary<string, Collection> collections
        )
        {
            var accounts = new List<Account>(items.Length);
            var sshKeys = new List<SshKey>(items.Length);
            List<ParseError> errors = null;

            foreach (var item in items)
            {
                try
                {
                    switch (item.Type)
                    {
                        case R.ItemType.Login:
                            accounts.Add(ParseAccountItem(item, vaultKey, orgKeys, folders, collections));
                            break;
                        case R.ItemType.SshKey:
                            sshKeys.Add(ParseSshKeyItem(item, vaultKey, orgKeys, folders, collections));
                            break;
                    }
                }
                catch (Exception e)
                {
                    errors ??= [];
                    errors.Add(new ParseError($"Failed to parse a vault item '{item.Id}' of type '{item.Type}'", e.Message, e.StackTrace));
                }
            }

            return ([.. accounts], [.. sshKeys], errors?.ToArray() ?? []);
        }

        internal static Account ParseAccountItem(
            R.Item item,
            byte[] vaultKey,
            Dictionary<string, byte[]> orgKeys,
            Dictionary<string, string> folders,
            Dictionary<string, Collection> collections
        )
        {
            var (vaultItem, key) = ParseVaultItem(item, vaultKey, orgKeys, folders, collections);
            return new Account(vaultItem)
            {
                Username = DecryptToStringOrBlank(item.Login.Username, key),
                Password = DecryptToStringOrBlank(item.Login.Password, key),
                Url = DecryptToStringOrBlank(item.Login.Uri, key),
                Totp = DecryptToStringOrBlank(item.Login.Totp, key),
            };
        }

        internal static SshKey ParseSshKeyItem(
            R.Item item,
            byte[] vaultKey,
            Dictionary<string, byte[]> orgKeys,
            Dictionary<string, string> folders,
            Dictionary<string, Collection> collections
        )
        {
            var (vaultItem, key) = ParseVaultItem(item, vaultKey, orgKeys, folders, collections);
            return new SshKey(vaultItem)
            {
                PublicKey = DecryptToStringOrBlank(item.SshKey.PublicKey, key),
                PrivateKey = DecryptToStringOrBlank(item.SshKey.PrivateKey, key),
                Fingerprint = DecryptToStringOrBlank(item.SshKey.Fingerprint, key),
            };
        }

        internal static (VaultItem, byte[] key) ParseVaultItem(
            R.Item item,
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

            var folder = item.FolderId != null && folders.ContainsKey(item.FolderId) ? folders[item.FolderId] : "";

            var parsedItem = new VaultItem
            {
                Id = item.Id,
                Name = DecryptToStringOrBlank(item.Name, key),
                Note = DecryptToStringOrBlank(item.Notes, key),
                DeletedDate = item.DeletedDate,
                Folder = folder,
                CollectionIds = item.CollectionIds ?? [],
                HidePassword = ResolveHidePassword(item.CollectionIds, collections),
                CustomFields = ParseCustomFields(item, key),
            };

            return (parsedItem, key);
        }

        internal static CustomField[] ParseCustomFields(R.Item item, byte[] key)
        {
            return item.Fields?.Select(x => ParseField(x, key, item)).ToArray() ?? [];
        }

        internal static CustomField ParseField(R.Field field, byte[] key, R.Item item)
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

        internal static string ResolveLinkedField(int? fieldLinkedId, byte[] key, R.Item item)
        {
            return fieldLinkedId switch
            {
                null => "",
                100 => DecryptToStringOrBlank(item.Login.Username, key),
                101 => DecryptToStringOrBlank(item.Login.Password, key),
                _ => throw new UnsupportedFeatureException($"Linked field ID {fieldLinkedId} is not supported"),
            };
        }

        internal static bool ResolveHidePassword(string[] collectionIds, Dictionary<string, Collection> collections)
        {
            // Items that don't have any collections associated with them cannot hide their password.
            if (collectionIds.Length == 0)
                return false;

            // Only hide the password when ALL the collections this item is in have "hide password" enabled.
            return collectionIds.All(x => collections.GetOrDefault(x, null)?.HidePasswords == true);
        }

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

        internal static BaseException MakeSpecializedError(RestResponse<string> response)
        {
            if (response.IsNetworkError)
                return new NetworkErrorException("Network error has occurred", response.Error);

            if (!IsHttp4XX(response))
                return new InternalErrorException($"Unexpected response from the server with status code {response.StatusCode}");

            // It's possible that the original request failed because of the JSON parsing, but we
            // ignore it deliberately to first check for returned errors.
            var error = GetServerError(response);
            if (!error.HasValue)
            {
                // Only when the error parsing failed we return the original error.
                if (response.HasError)
                    return new InternalErrorException("Network request or response parsing failed", response.Error);

                // We expect some error to be returned by the server.
                return new InternalErrorException("Unexpected response from the server");
            }

            var e = error.Value;
            var message = e.Info.Message ?? e.Description ?? e.Message ?? e.Id ?? "unknown error";

            if (message.Contains("Username or password is incorrect"))
                return new BadCredentialsException(message);

            if (message.Contains("Two-step token is invalid"))
                return new BadMultiFactorException(message);

            if (e.Id == "invalid_client")
                return new BadCredentialsException("Client ID or secret is incorrect");

            return new InternalErrorException($"Server responded with an error: '{message}'");
        }

        internal static R.Error? GetServerError(RestResponse<string> response)
        {
            try
            {
                return JsonConvert.DeserializeObject<R.Error>(response.Content ?? "{}");
            }
            catch (JsonException)
            {
                return null;
            }
        }

        internal static CanceledMultiFactorException MakeCancelledMfaError(Exception inner = null)
        {
            return new CanceledMultiFactorException("Second factor step is canceled by the user", inner);
        }

        internal static BadMultiFactorException MakeFailedMfaError(Exception inner = null)
        {
            return new BadMultiFactorException("Second factor step failed", inner);
        }

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

        private const string DefaultApiUrl = "https://api.bitwarden.com";
        private const string DefaultIdentityUrl = "https://identity.bitwarden.com";

        private const string RememberMeTokenKey = "remember-me-token";

        private const string CliVersion = "2025.2.0";
        private static readonly string Platform = GetPlatform();
        private static readonly string UserAgent = $"Bitwarden_CLI/{CliVersion} ({Platform.ToUpper()})";

        private static readonly string DeviceType = Platform switch
        {
            "windows" => "23",
            "macos" => "24",
            "linux" => "25",
            _ => throw new InternalErrorException($"Unexpected device name {Platform}"),
        };

        private static readonly Dictionary<string, string> DefaultRestHeaders = new Dictionary<string, string>
        {
            ["User-Agent"] = UserAgent,
            ["Device-Type"] = DeviceType,
            ["Bitwarden-Client-Name"] = "cli",
            ["Bitwarden-Client-Version"] = CliVersion,
        };

        private static readonly R.KdfInfo DefaultKdfInfo = new R.KdfInfo { Kdf = R.KdfMethod.Pbkdf2Sha256, Iterations = 5000 };
    }
}
