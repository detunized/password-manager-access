// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword.Ui;
using U2fWin10;
using R = PasswordManagerAccess.OnePassword.Response;

// Async refactoring TODO:
//
// [x] Make all networking methods async and take CancellationToken
// [ ] Check IAsyncEnumerable
// [ ] Make SecureStorage async
// [ ] Make UI async
// [ ] Make SRP async
// [ ] Switch to async Duo
// [ ] Convert to record types
// [ ] Convert to System.Text.Json

namespace PasswordManagerAccess.OnePassword
{
    public static partial class Client
    {
        public const string DefaultDomain = "my.1password.com";
        public const string ClientName = "1Password CLI";

        // TODO: Even though the CLI version doesn't seem to get outdated as quickly as the web one,
        //       it's possible this needs to be updated every now and then. Keep an eye on this.
        public const string ClientVersion = "2190004";
        public const string ClientId = ClientName + "/" + ClientVersion;

        //
        // SSO stubs
        //

        public static Task<bool> IsSsoAccount(string username, CancellationToken cancellationToken) => Task.FromResult(false);

        public static Task<Session> SsoLogIn(
            Credentials credentials,
            AppInfo app,
            IUi ui,
            ISecureStorage storage,
            CancellationToken cancellationToken
        ) => throw new NotImplementedException("SSO login is not implemented in this version of the library");

        // Public entries point to the library: Login, Logout, ListAllVaults, OpenVault
        // We try to mimic the remote structure, that's why there's an array of vaults.
        // We open all the ones we can.
        public static async Task<Session> LogIn(
            Credentials credentials,
            AppInfo app,
            IUi ui,
            ISecureStorage storage,
            CancellationToken cancellationToken
        )
        {
            var transport = new RestTransport();
            try
            {
                return await LogIn(credentials, app, ui, storage, transport, cancellationToken);
            }
            catch (Exception)
            {
                // We only need to dispose in case of an error, otherwise it's returned with the session.
                transport.Dispose();
                throw;
            }
        }

        // Service account access is intended for the CLI and the automation tools. It's not supposed to have
        // any 2FA used in the flow. Also we won't need to store anything between the sessions.
        public static async Task<Session> LogIn(ServiceAccount serviceAccount, AppInfo app, CancellationToken cancellationToken)
        {
            var credentials = ParseServiceAccountToken(serviceAccount.Token);
            return await LogIn(credentials, app, new Util.ThrowUi(), new Util.ThrowStorage(), cancellationToken);
        }

        public static async Task LogOut(Session session, CancellationToken cancellationToken)
        {
            try
            {
                await LogOut(session.Rest, cancellationToken);
            }
            finally
            {
                session.Transport.Dispose();
            }
        }

        public static async Task<VaultInfo[]> ListAllVaults(Session session, CancellationToken cancellationToken)
        {
            return await ListAllVaults(session.Credentials, session.Keychain, session.Key, session.Rest, cancellationToken);
        }

        public static async Task<Vault> OpenVault(VaultInfo info, Session session, CancellationToken cancellationToken)
        {
            // Make sure the vault key is in the keychain not to check on every account. They key decryption
            // is negligibly quick compared to the account retrieval, so we could do that upfront.
            info.DecryptKeyIntoKeychain();

            var (accounts, sshKeys) = await GetVaultItems(info.Id, session.Keychain, session.Key, session.Rest, cancellationToken);
            return new Vault(info, accounts, sshKeys);
        }

        public static async Task<OneOf<Account, SshKey, NoItem>> GetItem(
            string itemId,
            string vaultId,
            Session session,
            CancellationToken cancellationToken
        )
        {
            var oneOf3 = await GetVaultItem(itemId, vaultId, session.Keychain, session.Key, session.Rest, cancellationToken);

            // The item is not available
            if (oneOf3.TryPickT2(out var failure, out var oneOf2))
                return failure;

            var item = oneOf2.Match<VaultItem>(a => a, k => k);

            if (CanDecrypt(item))
                return oneOf3;

            // Attempt to fetch everything necessary to decrypt the item
            var accountInfo = await GetAccountInfo(session.Key, session.Rest, cancellationToken);
            var keysets = await GetKeysets(session.Key, session.Rest, cancellationToken);
            DecryptKeysets(keysets.Keysets, session.Credentials, session.Keychain);
            GetAccessibleVaults(accountInfo, session.Keychain).FirstOrDefault(x => x.Id == vaultId)?.DecryptKeyIntoKeychain();

            if (CanDecrypt(item))
                return oneOf3;

            throw new InternalErrorException("Failed to fetch the keys to decrypt the item");

            bool CanDecrypt(VaultItem i) => session.Keychain.CanDecrypt(i.EncryptedOverview) && session.Keychain.CanDecrypt(i.EncryptedDetails);
        }

        // Use this function to generate a unique random identifier for each new client.
        public static string GenerateRandomUuid()
        {
            return Util.RandomUuid();
        }

        //
        // Internal
        //

        internal static async Task<Session> LogIn(
            Credentials credentials,
            AppInfo app,
            IUi ui,
            ISecureStorage storage,
            IRestTransport transport,
            CancellationToken cancellationToken
        )
        {
            var rest = MakeRestClient(transport, GetApiUrl(credentials.Domain));
            var (sessionKey, sessionRest) = await LogIn(credentials, app, ui, storage, rest, cancellationToken);
            return new Session(credentials, new Keychain(), sessionKey, sessionRest, transport);
        }

        internal static Credentials ParseServiceAccountToken(string token)
        {
            static InternalErrorException Error(string detail, Exception inner = null)
            {
                return new InternalErrorException($"Invalid service account token: {detail}", inner);
            }

            static string Validate(string value, string name)
            {
                if (value.IsNullOrEmpty())
                    throw Error($"invalid {name}");

                return value;
            }

            if (token == null || !token.StartsWith("ops_"))
                throw Error("invalid format");

            R.ServiceAccountToken parsed;
            try
            {
                parsed = JsonConvert.DeserializeObject<R.ServiceAccountToken>(token.Substring(4).Decode64Loose().ToUtf8());
            }
            catch (JsonException e)
            {
                throw Error("failed to parse JSON", e);
            }

            if (parsed == null)
                throw Error("failed to parse JSON");

            return new Credentials
            {
                Username = Validate(parsed.Username, "username"),
                AccountKey = Validate(parsed.AccountKey, "account key"),
                Domain = Validate(parsed.Domain, "domain"),
                DeviceUuid = Validate(parsed.DeviceUuid, "device UUID"),
                SrpX = Validate(parsed.SrpX, "SRP X value"),
                Key = new AesKey(MasterKeyId, Validate(parsed.MasterUnlockKey.Key, "MUK").Decode64Loose()),
            };
        }

        internal static async Task<VaultInfo[]> ListAllVaults(
            Credentials credentials,
            Keychain keychain,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Step 1: Get account info. It contains users, keys, groups, vault info and other stuff.
            //         Not the actual vault data though. That is requested separately.
            var accountInfo = await GetAccountInfo(sessionKey, rest, cancellationToken);

            // Step 2: Get all the keysets in one place. The original code is quite hairy around this
            //         topic, so it's not very clear if these keysets should be merged with anything else
            //         or it's enough to just use these keys. For now we gonna ignore other keys and
            //         see if it's enough.
            var keysets = await GetKeysets(sessionKey, rest, cancellationToken);

            // Step 3: Derive and decrypt the keys
            DecryptKeysets(keysets.Keysets, credentials, keychain);

            // Step 4: Get all the vaults the user has access to
            var vaults = GetAccessibleVaults(accountInfo, keychain);

            // Done
            return vaults.ToArray();
        }

        // This is exception is used internally to trigger re-login from the depth of the call stack.
        // Possibly not the best design. TODO: Should this be done differently?
        internal class RetryLoginException : Exception { }

        internal static async Task<(AesKey, RestClient)> LogIn(
            Credentials credentials,
            AppInfo app,
            IUi ui,
            ISecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            while (true)
            {
                try
                {
                    return await LoginAttempt(credentials, app, ui, storage, rest, cancellationToken);
                }
                catch (RetryLoginException) { }
            }
        }

        private static async Task<(AesKey, RestClient)> LoginAttempt(
            Credentials credentials,
            AppInfo app,
            IUi ui,
            ISecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Step 1: Request to initiate a new session
            var (sessionId, srpInfo) = await StartNewSession(credentials, app, rest, cancellationToken);

            // After a new session has been initiated, all the subsequent requests must be
            // signed with the session ID.
            var sessionRest = MakeRestClient(rest, sessionId: sessionId);

            // Step 2: Perform SRP exchange
            var sessionKey = SrpV1.Perform(credentials, srpInfo, sessionId, sessionRest);

            // Assign a request signer now that we have a key.
            // All the following requests are expected to be signed with the MAC.
            var macRest = MakeRestClient(sessionRest, new MacRequestSigner(sessionKey), sessionId);

            // Step 3: Verify the key with the server
            var verifiedOrMfa = await VerifySessionKey(credentials, app, sessionKey, macRest, cancellationToken);

            // Step 4: Submit 2FA code if needed
            if (verifiedOrMfa.Status == VerifyStatus.SecondFactorRequired)
                await PerformSecondFactorAuthentication(verifiedOrMfa.Factors, credentials, sessionKey, ui, storage, macRest, cancellationToken);

            return (sessionKey, macRest);
        }

        internal static string GetApiUrl(string domain)
        {
            return $"https://{domain}/api";
        }

        // TODO: Rename to MakeRestClient after the migration is complete
        internal static RestClient MakeSystemJsonRestClient(
            IRestTransport transport,
            string baseUrl,
            IRequestSigner signer = null,
            string sessionId = null
        ) => MakeRestClientInternal(transport, baseUrl, signer, sessionId, useSystemJson: true);

        // TODO: Remove this after the migration to System.Text.Json is complete
        internal static RestClient MakeRestClient(IRestTransport transport, string baseUrl, IRequestSigner signer = null, string sessionId = null) =>
            MakeRestClientInternal(transport, baseUrl, signer, sessionId, useSystemJson: false);

        // TODO: Remove this after the migration to System.Text.Json is complete
        internal static RestClient MakeRestClientInternal(
            IRestTransport transport,
            string baseUrl,
            IRequestSigner signer = null,
            string sessionId = null,
            bool useSystemJson = false
        )
        {
            var headers = new Dictionary<string, string>(2) { ["X-AgileBits-Client"] = ClientId };
            if (!sessionId.IsNullOrEmpty())
                headers["X-AgileBits-Session-ID"] = sessionId;

            return new RestClient(transport, baseUrl, signer, headers, useSystemJson: useSystemJson);
        }

        internal static RestClient MakeSystemJsonRestClient(RestClient rest, IRequestSigner signer = null, string sessionId = null)
        {
            return MakeSystemJsonRestClient(rest.Transport, rest.BaseUrl, signer ?? rest.Signer, sessionId);
        }

        // TODO: Remove this after the migration to System.Text.Json is complete
        internal static RestClient MakeRestClient(RestClient rest, IRequestSigner signer = null, string sessionId = null)
        {
            return MakeRestClient(rest.Transport, rest.BaseUrl, signer ?? rest.Signer, sessionId);
        }

        internal static async Task<(string SessionId, SrpInfo SrpInfo)> StartNewSession(
            Credentials credentials,
            AppInfo app,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var url =
                $"v2/auth/{credentials.Username}/{credentials.ParsedAccountKey.Format}/{credentials.ParsedAccountKey.Uuid}/{credentials.DeviceUuid}";
            var response = await rest.GetAsync<R.NewSession>(url, cancellationToken);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var info = response.Data;
            var status = info.Status;
            switch (status)
            {
                case "ok":
                    if (info.KeyFormat != credentials.ParsedAccountKey.Format || info.KeyUuid != credentials.ParsedAccountKey.Uuid)
                        throw new BadCredentialsException("The account key is incorrect");

                    var srpInfo = new SrpInfo(
                        srpMethod: info.Auth.Method,
                        keyMethod: info.Auth.Algorithm,
                        iterations: info.Auth.Iterations,
                        salt: info.Auth.Salt.Decode64Loose()
                    );

                    return (info.SessionId, srpInfo);
                case "device-not-registered":
                    await RegisterDevice(credentials.DeviceUuid, app, MakeRestClient(rest, sessionId: info.SessionId), cancellationToken);
                    break;
                case "device-deleted":
                    await ReauthorizeDevice(credentials.DeviceUuid, app, MakeRestClient(rest, sessionId: info.SessionId), cancellationToken);
                    break;
                default:
                    throw new InternalErrorException($"Failed to start a new session, unsupported response status '{status}'");
            }

            return await StartNewSession(credentials, app, rest, cancellationToken);
        }

        internal static async Task RegisterDevice(string uuid, AppInfo app, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostJsonAsync<R.SuccessStatus>(
                "v1/device",
                new Dictionary<string, object>
                {
                    ["uuid"] = uuid,
                    ["clientName"] = ClientName,
                    ["clientVersion"] = ClientVersion,
                    ["osName"] = GetOsName(),
                    ["osVersion"] = "", // TODO: It's not so trivial to detect the proper OS version in .NET. Look into that.
                    ["name"] = app.Name,
                    ["model"] = app.Version,
                },
                cancellationToken
            );

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Success != 1)
                throw new InternalErrorException($"Failed to register the device '{uuid}'");
        }

        internal static async Task ReauthorizeDevice(string uuid, AppInfo app, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PutAsync<R.SuccessStatus>($"v1/device/{uuid}/reauthorize", cancellationToken);

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Success != 1)
                throw new InternalErrorException($"Failed to reauthorize the device '{uuid}'");
        }

        internal enum VerifyStatus
        {
            Success,
            SecondFactorRequired,
        }

        internal enum SecondFactorKind
        {
            GoogleAuthenticator,
            RememberMeToken,
            WebAuthn,
            Duo,
        }

        internal readonly struct SecondFactor
        {
            public readonly SecondFactorKind Kind;
            public readonly object Parameters;

            public SecondFactor(SecondFactorKind kind, object parameters = null)
            {
                Kind = kind;
                Parameters = parameters;
            }
        }

        internal readonly struct VerifyResult
        {
            public readonly VerifyStatus Status;
            public readonly SecondFactor[] Factors;

            public VerifyResult(VerifyStatus status)
                : this(status, new SecondFactor[0]) { }

            public VerifyResult(VerifyStatus status, SecondFactor[] factors)
            {
                Status = status;
                Factors = factors;
            }
        }

        internal static async Task<VerifyResult> VerifySessionKey(
            Credentials credentials,
            AppInfo app,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var response = await PostEncryptedJsonAsync<R.VerifyKey>(
                "v2/auth/verify",
                new Dictionary<string, object>
                {
                    ["sessionID"] = sessionKey.Id,
                    ["clientVerifyHash"] = Util.CalculateClientHash(credentials.ParsedAccountKey.Uuid, sessionKey.Id),
                    ["client"] = ClientId,
                    ["device"] = new Dictionary<string, string>
                    {
                        ["uuid"] = credentials.DeviceUuid,
                        ["clientName"] = ClientName,
                        ["clientVersion"] = ClientVersion,
                        ["name"] = app.Name,
                        ["model"] = app.Version,
                        ["osName"] = GetOsName(),
                        ["osVersion"] = "", // TODO: It's not so trivial to detect the proper OS version in .NET.
                        // Look into that.
                        ["userAgent"] = "", // TODO: The browser uses a user agent string here. We need to figure out
                        // what CLI sends. This is not trivial at all because of the E2E encryption.
                    },
                },
                sessionKey,
                rest,
                cancellationToken
            );

            // TODO: 1P verifies if "serverVerifyHash" is valid. Do that.
            // We assume it's all good if we got HTTP 200.

            var mfa = response.Mfa;
            if (mfa == null)
                return new VerifyResult(VerifyStatus.Success);

            return new VerifyResult(VerifyStatus.SecondFactorRequired, GetSecondFactors(mfa));
        }

        internal static SecondFactor[] GetSecondFactors(R.MfaInfo mfa)
        {
            var factors = new List<SecondFactor>(2);

            if (mfa.GoogleAuth?.Enabled == true)
                factors.Add(new SecondFactor(SecondFactorKind.GoogleAuthenticator));

            if (mfa.RememberMe?.Enabled == true)
                factors.Add(new SecondFactor(SecondFactorKind.RememberMeToken));

            if (mfa.WebAuthn?.Enabled == true)
                factors.Add(new SecondFactor(SecondFactorKind.WebAuthn, mfa.WebAuthn));

            if (mfa.Duo?.Enabled == true)
                factors.Add(new SecondFactor(SecondFactorKind.Duo, mfa.Duo));

            if (factors.Count == 0)
                throw new InternalErrorException("No supported 2FA methods found");

            return factors.ToArray();
        }

        internal static async Task PerformSecondFactorAuthentication(
            SecondFactor[] factors,
            Credentials credentials,
            AesKey sessionKey,
            IUi ui,
            ISecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Try "remember me" first. It's possible the server didn't allow it or
            // we don't have a valid token stored from one of the previous sessions.
            if (await TrySubmitRememberMeToken(factors, sessionKey, storage, rest, cancellationToken))
                return;

            // TODO: Allow to choose 2FA method via UI like in Bitwarden
            var factor = ChooseInteractiveSecondFactor(factors);

            var secondFactorResult = await GetSecondFactorResult(factor, credentials, ui, rest, cancellationToken);
            if (secondFactorResult.Canceled)
                throw new CanceledMultiFactorException("Second factor step is canceled by the user");

            var token = await SubmitSecondFactorResult(factor.Kind, secondFactorResult, sessionKey, rest, cancellationToken);

            // Store the token with the application. Next time we're not gonna need to enter any passcodes.
            if (secondFactorResult.RememberMe)
                storage.StoreString(RememberMeTokenKey, token);
        }

        internal static async Task<bool> TrySubmitRememberMeToken(
            SecondFactor[] factors,
            AesKey sessionKey,
            ISecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            if (factors.All(x => x.Kind != SecondFactorKind.RememberMeToken))
                return false;

            var token = storage.LoadString(RememberMeTokenKey);
            if (string.IsNullOrEmpty(token))
                return false;

            var result = SecondFactorResult.Done(
                new Dictionary<string, string> { ["dshmac"] = Util.HashRememberMeToken(token, sessionKey.Id) },
                true
            );

            try
            {
                await SubmitSecondFactorResult(SecondFactorKind.RememberMeToken, result, sessionKey, rest, cancellationToken);
            }
            catch (BadMultiFactorException)
            {
                // The token got rejected, need to erase it, it's no longer valid.
                storage.StoreString(RememberMeTokenKey, null);

                // When the stored 'remember me' token is rejected by the server, we need to try
                // the whole login sequence one more time. Probably the token is expired or it's
                // invalid.
                throw new RetryLoginException();
            }

            return true;
        }

        internal static SecondFactor ChooseInteractiveSecondFactor(SecondFactor[] factors)
        {
            if (factors.Length == 0)
                throw new InternalErrorException("The list of 2FA methods is empty");

            // We have O(N^2) here, but it's ok, since it's at most just a handful of elements.
            // Converting them to a hash set would take longer.
            foreach (var i in SecondFactorPriority)
            foreach (var f in factors)
                if (f.Kind == i)
                    return f;

            throw new InternalErrorException("The list of 2FA methods doesn't contain any supported methods");
        }

        internal class SecondFactorResult
        {
            public readonly Dictionary<string, string> Parameters;
            public readonly bool RememberMe;
            public readonly bool Canceled;
            public readonly string Note; // Let the 2FA attach a note

            public static SecondFactorResult Done(Dictionary<string, string> parameters, bool rememberMe, string note = "")
            {
                return new SecondFactorResult(parameters: parameters, rememberMe: rememberMe, canceled: false, note: note);
            }

            public static SecondFactorResult Cancel()
            {
                return new SecondFactorResult(parameters: null, rememberMe: false, canceled: true);
            }

            private SecondFactorResult(Dictionary<string, string> parameters, bool rememberMe, bool canceled, string note = "")
            {
                Parameters = parameters;
                RememberMe = rememberMe;
                Canceled = canceled;
                Note = note;
            }
        }

        internal static async Task<SecondFactorResult> GetSecondFactorResult(
            SecondFactor factor,
            Credentials credentials,
            IUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            return factor.Kind switch
            {
                SecondFactorKind.GoogleAuthenticator => await AuthenticateWithGoogleAuth(ui, cancellationToken),
                SecondFactorKind.WebAuthn => await AuthenticateWithWebAuthn(factor, credentials, ui, cancellationToken),
                SecondFactorKind.Duo => await AuthenticateWithDuo(factor, ui, rest, cancellationToken),
                _ => throw new InternalErrorException($"2FA method {factor.Kind} is not valid here"),
            };
        }

        internal static async Task<SecondFactorResult> AuthenticateWithGoogleAuth(IUi ui, CancellationToken cancellationToken)
        {
            var passcode = await ui.ProvideGoogleAuthPasscode(cancellationToken);
            if (passcode == Passcode.Cancel)
                return SecondFactorResult.Cancel();

            return SecondFactorResult.Done(new Dictionary<string, string> { ["code"] = passcode.Code }, passcode.RememberMe);
        }

        internal static async Task<SecondFactorResult> AuthenticateWithWebAuthn(
            SecondFactor factor,
            Credentials credentials,
            IUi ui,
            CancellationToken cancellationToken
        )
        {
            var rememberMe = await ui.ProvideWebAuthnRememberMe(cancellationToken);
            if (rememberMe == Passcode.Cancel)
                return SecondFactorResult.Cancel();

            if (!(factor.Parameters is R.WebAuthnMfa extra))
                throw new InternalErrorException("WebAuthn extra parameters expected");

            if (extra.KeyHandles.Length == 0)
                throw new InternalErrorException("Expected at least one WebAuthn key to be provided");

            try
            {
                // TODO: Make this async
                var assertion = WebAuthN.GetAssertion(
                    appId: "1password." + Util.GetTld(credentials.Domain),
                    challenge: extra.Challenge,
                    origin: $"https://{credentials.Domain}",
                    crossOrigin: false,
                    keyHandles: extra.KeyHandles
                );

                return SecondFactorResult.Done(
                    new Dictionary<string, string>
                    {
                        ["keyHandle"] = assertion.KeyHandle,
                        ["signature"] = assertion.Signature,
                        ["authData"] = assertion.AuthData,
                        ["clientData"] = assertion.ClientData,
                    },
                    rememberMe.RememberMe
                );
            }
            catch (CanceledException)
            {
                return SecondFactorResult.Cancel();
            }
            catch (ErrorException e)
            {
                throw new InternalErrorException("WebAuthn authentication failed", e);
            }
        }

        internal static async Task<SecondFactorResult> AuthenticateWithDuo(
            SecondFactor factor,
            IUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            if (!(factor.Parameters is R.DuoMfa extra))
                throw new InternalErrorException("Duo extra parameters expected");

            static string CheckParam(string param, string name)
            {
                if (param.IsNullOrEmpty())
                    throw new InternalErrorException($"Duo parameter '{name}' is invalid");

                return param;
            }

            // TODO: Switch to async Duo
            var isV1 = extra.Url.IsNullOrEmpty();
            var result = isV1
                ? DuoV1.Authenticate(CheckParam(extra.Host, "host"), CheckParam(extra.Signature, "sigRequest"), ui, rest.Transport)
                : DuoV4.Authenticate(extra.Url, ui, rest.Transport);

            if (result == null)
                return SecondFactorResult.Cancel();

            var key = isV1 ? "sigResponse" : "code";
            var note = isV1 ? "v1" : "v4";
            return SecondFactorResult.Done(new Dictionary<string, string> { [key] = result.Code }, result.RememberMe, note);
        }

        // Returns "remember me" token when successful
        internal static async Task<string> SubmitSecondFactorResult(
            SecondFactorKind factor,
            SecondFactorResult result,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var key = factor switch
            {
                SecondFactorKind.GoogleAuthenticator => "totp",
                SecondFactorKind.RememberMeToken => "dsecret",
                SecondFactorKind.WebAuthn => "webAuthn",
                SecondFactorKind.Duo => result.Note switch
                {
                    "v1" => "duo",
                    "v4" => "duov4",
                    _ => throw new InternalErrorException($"Invalid Duo version '{result.Note}'"),
                },
                _ => throw new InternalErrorException($"2FA method {factor} is not valid"),
            };

            try
            {
                var response = await PostEncryptedJsonAsync<R.Mfa>(
                    "v1/auth/mfa",
                    new Dictionary<string, object>
                    {
                        ["sessionID"] = sessionKey.Id,
                        ["client"] = ClientId,
                        [key] = result.Parameters,
                    },
                    sessionKey,
                    rest,
                    cancellationToken
                );

                return response.RememberMeToken;
            }
            catch (BadCredentialsException e)
            {
                // The server report everything as "no auth" error. In this case we know it's related to the MFA.
                throw new BadMultiFactorException("Incorrect second factor code", e.InnerException);
            }
        }

        internal static async Task<R.AccountInfo> GetAccountInfo(AesKey sessionKey, RestClient rest, CancellationToken cancellationToken)
        {
            return await GetEncryptedJsonAsync<R.AccountInfo>(
                "v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults",
                sessionKey,
                rest,
                cancellationToken
            );
        }

        internal static async Task<R.KeysetsInfo> GetKeysets(AesKey sessionKey, RestClient rest, CancellationToken cancellationToken)
        {
            return await GetEncryptedJsonAsync<R.KeysetsInfo>("v1/account/keysets", sessionKey, rest, cancellationToken);
        }

        internal static IEnumerable<VaultInfo> GetAccessibleVaults(R.AccountInfo accountInfo, Keychain keychain)
        {
            return from vault in accountInfo.Vaults
                let key = FindWorkingKey(vault.Access, keychain)
                where key != null
                select new VaultInfo(vault.Id, Encrypted.Parse(vault.Attributes), key, keychain);
        }

        internal static Encrypted FindWorkingKey(R.VaultAccessInfo[] accessList, Keychain keychain)
        {
            foreach (var access in accessList)
            {
                if (IsReadAccessible(access.Acl))
                {
                    var key = Encrypted.Parse(access.EncryptedKey);
                    if (keychain.CanDecrypt(key))
                        return key;
                }
            }

            return null;
        }

        internal static bool IsReadAccessible(int acl)
        {
            const int haveReadAccess = 32;
            return (acl & haveReadAccess) != 0;
        }

        // TODO: Add a test to verify the deleted accounts are ignored
        internal static async Task<(Account[], SshKey[])> GetVaultItems(
            string id,
            Keychain keychain,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var accounts = new List<Account>();
            var sshKeys = new List<SshKey>();

            foreach (var item in await EnumerateAccountsItemsInVault(id, sessionKey, rest, cancellationToken))
            {
                switch (ConvertVaultItem(keychain, item).Value)
                {
                    case Account account:
                        accounts.Add(account);
                        break;
                    case SshKey sshKey:
                        sshKeys.Add(sshKey);
                        break;
                    case bool:
                        // Deleted item or unsupported, silently ignore
                        break;
                }
            }

            return (accounts.ToArray(), sshKeys.ToArray());
        }

        internal static OneOf<Account, SshKey, NoItem> ConvertVaultItem(Keychain keychain, R.VaultItem item)
        {
            if (item.Deleted == "Y")
                return NoItem.Deleted;

            return item.TemplateId switch
            {
                Account.LoginTemplateId or Account.ServerTemplateId => new Account(item, keychain),
                SshKey.SshKeyTemplateId => new SshKey(item, keychain),
                _ => NoItem.UnsupportedType,
            };
        }

        internal static async Task<OneOf<Account, SshKey, NoItem>> GetVaultItem(
            string itemId,
            string vaultId,
            Keychain keychain,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var response = await rest.GetAsync<R.Encrypted>($"v1/vault/{vaultId}/item/{itemId}", cancellationToken);
            if (response.IsSuccessful)
                return ConvertVaultItem(keychain, DecryptResponse<R.SingleVaultItem>(response.Data, sessionKey).Item);

            // Special case: the item not found
            if (response.StatusCode == System.Net.HttpStatusCode.BadRequest && response.Content.Trim() == "{}")
                return NoItem.NotFound;

            throw MakeError(response);
        }

        // TODO: Rename to RequestVaultAccounts? It should clearer from the name that it's a slow operation.
        // Don't enumerate more than once. It's very slow since it makes network requests.
        internal static async IAsyncEnumerable<R.VaultItem> EnumerateAccountsItemsInVault(
            string id,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var batchId = 0;
            while (true)
            {
                var batch = await GetEncryptedJsonAsync<R.VaultItemsBatch>($"v1/vault/{id}/{batchId}/items", sessionKey, rest, cancellationToken);
                if (batch.Items != null)
                    foreach (var i in batch.Items)
                        yield return i;

                // The last batch is marked with {batchComplete: true}
                if (batch.Complete)
                    yield break;

                batchId = batch.Version;
            }
        }

        internal static async Task LogOut(RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PutAsync<R.SuccessStatus>("v1/session/signout", cancellationToken);

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Success != 1)
                throw new InternalErrorException("Failed to logout");
        }

        internal static void DecryptKeysets(R.KeysetInfo[] keysets, Credentials credentials, Keychain keychain)
        {
            // Find the master keyset
            var masterKeyset = keysets.Where(x => x.EncryptedBy == MasterKeyId).OrderByDescending(x => x.SerialNumber).FirstOrDefault();

            if (masterKeyset is null)
                throw new InternalErrorException("Master keyset not found");

            // Derive the master key. The rest of the keyset should decrypt by master or its derivatives.
            // In case we're logged in via a service account, we should have the master unlock key (MUK)
            // already provided by the token itself. It's passed in the credentials.
            var keyInfo = masterKeyset.KeyOrMasterKey;
            var masterKey =
                credentials.Key
                ?? DeriveMasterKey(
                    algorithm: keyInfo.Algorithm,
                    iterations: keyInfo.Iterations,
                    salt: keyInfo.Salt.Decode64Loose(),
                    credentials: credentials
                );
            keychain.Add(masterKey);

            // Build a topological map: key -> other keys encrypted by that key
            var encryptsKeysets = new Dictionary<string, List<R.KeysetInfo>>();
            foreach (var keyset in keysets)
                encryptsKeysets.GetOrAdd(GetEncryptedBy(keyset), () => new List<R.KeysetInfo>()).Add(keyset);

            // Start from "mp" and topologically walk the keys in a valid decryption order
            var queue = new Queue<R.KeysetInfo>(encryptsKeysets[MasterKeyId]);
            while (queue.Count > 0)
            {
                var keyset = queue.Dequeue();
                DecryptKeyset(keyset, keychain);

                // If the newly decrypted key encrypts some other keys, add them to the back of the queue
                if (encryptsKeysets.TryGetValue(keyset.Id, out var newKeysets))
                    foreach (var newKeyset in newKeysets)
                        queue.Enqueue(newKeyset);
            }
        }

        internal static string GetEncryptedBy(R.KeysetInfo keyset)
        {
            return keyset.EncryptedBy.IsNullOrEmpty() ? keyset.KeyOrMasterKey.KeyId : keyset.EncryptedBy;
        }

        internal static void DecryptKeyset(R.KeysetInfo keyset, Keychain keychain)
        {
            Util.DecryptAesKey(keyset.KeyOrMasterKey, keychain);
            Util.DecryptRsaKey(keyset.PrivateKey, keychain);
        }

        internal static AesKey DeriveMasterKey(string algorithm, int iterations, byte[] salt, Credentials credentials)
        {
            // TODO: Check if the Unicode normalization is the correct one. This could be done
            //       by either trying to call the original JS functions in the browser console
            //       or by changing to some really weird password and trying to log in.

            var k1 = Util.Hkdf(algorithm, salt, credentials.Username.ToLowerInvariant().ToBytes());
            var k2 = Util.Pbes2(algorithm, credentials.Password.Normalize(), k1, iterations);
            var key = credentials.ParsedAccountKey.CombineWith(k2);

            return new AesKey(MasterKeyId, key);
        }

        //
        // HTTP
        //

        internal static BaseException MakeError(RestResponse<string> response)
        {
            if (response.IsNetworkError)
                return new NetworkErrorException("Network error has occurred", response.Error);

            var serverError = ParseServerError(response.Content);
            if (serverError != null)
                return serverError;

            return new InternalErrorException($"Invalid or unexpected response from the server (HTTP status: {response.StatusCode})", response.Error);
        }

        // Returns null when no error is found
        internal static BaseException ParseServerError(string response)
        {
            try
            {
                var error = JsonConvert.DeserializeObject<R.Error>(response);
                switch (error.Code)
                {
                    case 102:
                        return new BadCredentialsException("Username, password or account key is incorrect");
                    default:
                        return new InternalErrorException($"The server responded with the error code {error.Code} and the message '{error.Message}'");
                }
            }
            catch (JsonException)
            {
                // Ignore, it wasn't a server error
            }

            try
            {
                var reason = JsonConvert.DeserializeObject<R.FailureReason>(response).Reason;
                if (!reason.IsNullOrEmpty())
                    return new InternalErrorException($"The server responded with the failure reason: '{reason}'");
            }
            catch (JsonException)
            {
                // Ignore, it wasn't a server error
            }

            return null;
        }

        internal static async Task<T> GetEncryptedJsonAsync<T>(
            string endpoint,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var response = await rest.GetAsync<R.Encrypted>(endpoint, cancellationToken);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return DecryptResponse<T>(response.Data, sessionKey);
        }

        internal static async Task<T> PostEncryptedJsonAsync<T>(
            string endpoint,
            Dictionary<string, object> parameters,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var encrypted = await PostEncryptedJsonNoDecryptAsync<R.Encrypted>(endpoint, parameters, sessionKey, rest, cancellationToken);
            return DecryptResponse<T>(encrypted, sessionKey);
        }

        internal static async Task<T> PostEncryptedJsonNoDecryptAsync<T>(
            string endpoint,
            Dictionary<string, object> parameters,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var payload = JsonConvert.SerializeObject(parameters);
            var encryptedPayload = sessionKey.Encrypt(payload.ToBytes());

            var response = await rest.PostJsonAsync<T>(endpoint, encryptedPayload.ToDictionary(), cancellationToken);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data;
        }

        internal static T DecryptResponse<T>(R.Encrypted encrypted, IDecryptor decryptor)
        {
            var plaintext = decryptor.Decrypt(Encrypted.Parse(encrypted)).ToUtf8();

            // First check for server errors. It's possible to deserialize the returned error object
            // into one of the target types by mistake when the type has no mandatory fields.
            // `Response.Mfa` would be one of those.
            if (ParseServerError(plaintext) is { } serverError)
                throw serverError;

            try
            {
                return JsonConvert.DeserializeObject<T>(plaintext);
            }
            catch (JsonException e)
            {
                throw new InternalErrorException("Failed to parse JSON in response from the server", e);
            }
        }

        internal static string GetOsName()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return "Windows";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return "macOS";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return "Linux";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Create("iOS")))
                return "iOS";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Create("Android")))
                return "Android";

            return "Unknown";
        }

        //
        // Private
        //

        private const string MasterKeyId = "mp";
        private const string RememberMeTokenKey = "remember-me-token";

        private static SecondFactorKind[] SecondFactorPriority =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? SecondFactorPriorityWindows : SecondFactorPriorityOtherPlatforms;

        private static readonly SecondFactorKind[] SecondFactorPriorityWindows =
        {
            SecondFactorKind.WebAuthn,
            SecondFactorKind.Duo,
            SecondFactorKind.GoogleAuthenticator,
        };

        private static readonly SecondFactorKind[] SecondFactorPriorityOtherPlatforms =
        {
            SecondFactorKind.Duo,
            SecondFactorKind.GoogleAuthenticator,
        };
    }
}
