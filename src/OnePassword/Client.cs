// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using OneOf;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword.Ui;
using U2fWin10;

namespace PasswordManagerAccess.OnePassword
{
    // TODO:
    // [x] implement mfa method selection
    // [x] implement mfa attempts
    // [ ] figure out if webauthn is possible on macos

    public static class Client
    {
        public const string DefaultDomain = "my.1password.com";
        public const string ClientName = "1Password CLI";

        // TODO: Even though the CLI version doesn't seem to get outdated as quickly as the web one,
        //       it's possible this needs to be updated every now and then. Keep an eye on this.
        public const string ClientVersion = "2190004";
        public const string ClientId = ClientName + "/" + ClientVersion;

        public const int MaxOtpAttempts = 3;

        //
        // SSO stubs
        //

        public static bool IsSsoAccount(string username) => false;

        public static Task<Session> SsoLogIn(
            Credentials credentials,
            AppInfo app,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            CancellationToken cancellationToken
        ) => throw new NotImplementedException("SSO login is not implemented in this version of the library");

        // Public entries point to the library: Login, Logout, ListAllVaults, OpenVault
        // We try to mimic the remote structure, that's why there's an array of vaults.
        // We open all the ones we can.
        public static async Task<Session> LogIn(
            Credentials credentials,
            AppInfo app,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            CancellationToken cancellationToken
        )
        {
            var transport = new RestTransport();
            try
            {
                return await LogIn(credentials, app, ui, storage, transport, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // We only need to dispose in case of an error, otherwise it's returned with the session.
                transport.Dispose();
                throw;
            }
        }

        // Service account access is intended for the CLI and the automation tools. It's not supposed to have
        // any 2FA used in the flow. Also, we won't need to store anything between the sessions.
        public static async Task<Session> LogIn(ServiceAccount serviceAccount, AppInfo app, CancellationToken cancellationToken)
        {
            var credentials = ParseServiceAccountToken(serviceAccount.Token);
            return await LogIn(credentials, app, new Util.ThrowUi(), new Util.ThrowStorage(), cancellationToken).ConfigureAwait(false);
        }

        public static async Task LogOut(Session session, CancellationToken cancellationToken)
        {
            try
            {
                await LogOut(session.Rest, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                session.Dispose();
            }
        }

        public static async Task<VaultInfo[]> ListAllVaults(Session session, CancellationToken cancellationToken)
        {
            return await ListAllVaults(session.Credentials, session.Keychain, session.Key, session.Rest, cancellationToken).ConfigureAwait(false);
        }

        public static async Task<Vault> OpenVault(VaultInfo info, Session session, CancellationToken cancellationToken)
        {
            // Make sure the vault key is in the keychain not to check on every account. They key decryption
            // is negligibly quick compared to the account retrieval, so we could do that upfront.
            info.DecryptKeyIntoKeychain();

            var (accounts, sshKeys) = await GetVaultItems(info.Id, session.Keychain, session.Key, session.Rest, cancellationToken)
                .ConfigureAwait(false);
            return new Vault(info, accounts, sshKeys);
        }

        public static async Task<OneOf<Account, SshKey, NoItem>> GetItem(
            string itemId,
            string vaultId,
            Session session,
            CancellationToken cancellationToken
        )
        {
            // 1. On the first request we fetch everything we need to decrypt the item. This is also allows us to check
            // upfront if the vault exists and if it's accessible.
            if (session.AccountInfo == null)
            {
                var accountInfo = await GetAccountInfo(session.Key, session.Rest, cancellationToken).ConfigureAwait(false);
                var keysetsInfo = await GetKeysets(session.Key, session.Rest, cancellationToken).ConfigureAwait(false);

                // Decrypt into the session keychain
                DecryptKeysets(keysetsInfo.Keysets, session.Credentials, session.Keychain);

                // Figure out which vaults are accessible with the current keychain
                var accessibleVaults = GetAccessibleVaults(accountInfo, session.Keychain).ToArray();

                // Decrypt all the vault keys into the session keychain
                foreach (var v in accessibleVaults)
                    v.DecryptKeyIntoKeychain();

                // Store last to ensure consistent state
                session.AccountInfo = accountInfo;
                session.AccessibleVaults = accessibleVaults;
            }

            // 2. Check if the vault ID is valid and the vault exists
            if (session.AccountInfo!.Vaults.All(x => x.Id != vaultId))
                return NoItem.NotFound;

            // 3. Even if the vault is there, it might not be accessible
            if (session.AccessibleVaults!.All(x => x.Id != vaultId))
                return NoItem.Inaccessible;

            // 4. Download the item
            var oneOf3 = await GetVaultItem(itemId, vaultId, session.Keychain, session.Key, session.Rest, cancellationToken).ConfigureAwait(false);

            // 5. Check if the item is not available
            if (oneOf3.TryPickT2(out var noItem, out var oneOf2))
                return noItem;

            // 6. It's either an account or an SSH key
            var item = oneOf2.Match<VaultItem>(a => a, k => k);

            if (CanDecrypt(item))
                return oneOf3;

            return NoItem.Inaccessible;

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
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            IRestTransport transport,
            CancellationToken cancellationToken
        )
        {
            var rest = MakeRestClient(transport, GetApiUrl(credentials.Domain));
            return await LogIn(credentials, app, ui, storage, rest, cancellationToken).ConfigureAwait(false);
        }

        internal static Credentials ParseServiceAccountToken(string token)
        {
            if (token == null || !token.StartsWith("ops_"))
                throw Error("invalid format");

            Model.ServiceAccountToken parsed;
            try
            {
                parsed = JsonSerializer.Deserialize<Model.ServiceAccountToken>(token.Substring(4).Decode64Loose().ToUtf8());
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
                Key = new AesKey(MasterKeyId, Validate(parsed.MasterUnlockKey!.Key, "MUK").Decode64Loose()),
            };

            // ---

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
            var accountInfo = await GetAccountInfo(sessionKey, rest, cancellationToken).ConfigureAwait(false);

            // Step 2: Get all the keysets in one place. The original code is quite hairy around this
            //         topic, so it's not very clear if these keysets should be merged with anything else,
            //         or it's enough to just use these keys. For now, we are going to ignore other keys and
            //         see if it's enough.
            var keysets = await GetKeysets(sessionKey, rest, cancellationToken).ConfigureAwait(false);

            // Step 3: Derive and decrypt the keys
            DecryptKeysets(keysets.Keysets, credentials, keychain);

            // Step 4: Get all the vaults the user has access to
            var vaults = GetAccessibleVaults(accountInfo, keychain);

            // Done
            return vaults.ToArray();
        }

        internal static async Task<Session> LogIn(
            Credentials credentials,
            AppInfo app,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Unlike other PM services, 1P doesn't like multiple OTP failures in a row.
            // After a failed attempt, we need to restart the whole auth sequence from scratch.
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    var result = await LoginAttempt(attempt, credentials, app, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                    switch (result.Value)
                    {
                        case Session session:
                            return session;
                        case MfaRetry:
                            // This is not a real attempt, this means the remember-me token got rejected by the server.
                            attempt--;
                            continue;
                        default:
                            throw new InternalErrorException("Invalid LoginAttempt result");
                    }
                }
                catch (BadMultiFactorException) when (attempt < MaxOtpAttempts - 1)
                {
                    // This bubbles up from the deep. A few times we allow the user to try again.
                    // After that, the exception is propagated all the way to the top.
                }
            }
        }

        internal struct MfaSuccess;

        internal struct MfaRetry;

        private static async Task<OneOf<Session, MfaRetry>> LoginAttempt(
            int attempt,
            Credentials credentials,
            AppInfo app,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Step 1: Request to initiate a new session
            var (sessionId, srpInfo) = await StartNewSession(credentials, app, rest, cancellationToken).ConfigureAwait(false);

            // After a new session has been initiated, all the subsequent requests must be
            // signed with the session ID.
            var sessionRest = MakeRestClient(rest, sessionId: sessionId);

            // Step 2: Perform SRP exchange
            var sessionKey = await SrpV1.PerformAsync(credentials, srpInfo, sessionId, sessionRest, cancellationToken).ConfigureAwait(false);

            // Assign a request signer now that we have a key.
            // All the following requests are expected to be signed with the MAC.
            var macRest = MakeRestClient(sessionRest, new MacRequestSigner(sessionKey), sessionId);

            // Step 3: Verify the key with the server
            var verifiedOrMfa = await VerifySessionKey(credentials, app, sessionKey, macRest, cancellationToken).ConfigureAwait(false);

            // Step 4: Submit 2FA code if needed
            if (verifiedOrMfa.Status == VerifyStatus.SecondFactorRequired)
            {
                var mfaResult = await PerformSecondFactorAuthentication(
                        attempt,
                        verifiedOrMfa.Factors,
                        credentials,
                        sessionKey,
                        ui,
                        storage,
                        macRest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                if (mfaResult.TryPickT1(out var retry, out _))
                    return retry;
            }

            return new Session(credentials, new Keychain(), sessionKey, macRest);
        }

        internal static string GetApiUrl(string domain)
        {
            return $"https://{domain}/api";
        }

        internal static RestClient MakeRestClient(IRestTransport transport, string baseUrl, IRequestSigner signer = null, string sessionId = null)
        {
            var headers = new Dictionary<string, string>(2) { ["X-AgileBits-Client"] = ClientId };
            if (!sessionId.IsNullOrEmpty())
                headers["X-AgileBits-Session-ID"] = sessionId;

            return new RestClient(transport, baseUrl, signer, headers, useSystemJson: true);
        }

        internal static RestClient MakeRestClient(RestClient rest, IRequestSigner signer = null, string sessionId = null) =>
            MakeRestClient(rest.Transport, rest.BaseUrl, signer ?? rest.Signer, sessionId);

        internal static async Task<(string SessionId, SrpInfo SrpInfo)> StartNewSession(
            Credentials credentials,
            AppInfo app,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var url =
                $"v2/auth/{credentials.Username}/{credentials.ParsedAccountKey.Format}/{credentials.ParsedAccountKey.Uuid}/{credentials.DeviceUuid}";

            var response = await rest.GetAsync<Model.NewSession>(url, cancellationToken).ConfigureAwait(false);
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
                        srpMethod: info.Auth!.Method,
                        keyMethod: info.Auth.Algorithm,
                        iterations: info.Auth.Iterations,
                        salt: info.Auth.Salt.Decode64Loose()
                    );

                    return (info.SessionId, srpInfo);

                case "device-not-registered":
                    await RegisterDevice(credentials.DeviceUuid, app, MakeRestClient(rest, sessionId: info.SessionId), cancellationToken)
                        .ConfigureAwait(false);
                    break;

                case "device-deleted":
                    await ReauthorizeDevice(credentials.DeviceUuid, app, MakeRestClient(rest, sessionId: info.SessionId), cancellationToken)
                        .ConfigureAwait(false);
                    break;

                default:
                    throw new InternalErrorException($"Failed to start a new session, unsupported response status '{status}'");
            }

            return await StartNewSession(credentials, app, rest, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task RegisterDevice(string uuid, AppInfo app, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostJsonAsync<Model.SuccessStatus>(
                    "v1/device",
                    new Dictionary<string, object>
                    {
                        ["uuid"] = uuid,
                        ["clientName"] = ClientName,
                        ["clientVersion"] = ClientVersion,
                        ["osName"] = GetOsName(),
                        ["osVersion"] = "", // TODO: It's not so trivial to detect the proper OS version in .NET. Look into that!
                        ["name"] = app.Name,
                        ["model"] = app.Version,
                    },
                    cancellationToken
                )
                .ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Success != 1)
                throw new InternalErrorException($"Failed to register the device '{uuid}'");
        }

        internal static async Task ReauthorizeDevice(string uuid, AppInfo app, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PutAsync<Model.SuccessStatus>($"v1/device/{uuid}/reauthorize", cancellationToken).ConfigureAwait(false);

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

        internal record SecondFactor(MfaMethod Method, object Parameters = null);

        internal readonly record struct VerifyResult(VerifyStatus Status, SecondFactor[] Factors);

        internal static async Task<VerifyResult> VerifySessionKey(
            Credentials credentials,
            AppInfo app,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var response = await PostEncryptedJson<Model.VerifyKey>(
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
                            // TODO: It's not so trivial to detect the proper OS version in .NET. Look into that!
                            ["osVersion"] = "",
                            // TODO: The browser uses a user agent string here. We need to figure out what CLI sends.
                            //       This is not trivial at all because of the E2E encryption.
                            ["userAgent"] = "",
                        },
                    },
                    sessionKey,
                    rest,
                    cancellationToken
                )
                .ConfigureAwait(false);

            // TODO: 1P verifies if "serverVerifyHash" is valid. Do that.
            // We assume it's all good if we got HTTP 200.

            var mfa = response.Mfa;
            if (mfa == null)
                return new VerifyResult(VerifyStatus.Success, []);

            return new VerifyResult(VerifyStatus.SecondFactorRequired, GetSecondFactors(mfa));
        }

        internal static SecondFactor[] GetSecondFactors(Model.MfaInfo mfa)
        {
            var factors = new List<SecondFactor>(2);

            if (mfa.GoogleAuth?.Enabled == true)
                factors.Add(new SecondFactor(MfaMethod.GoogleAuthenticator));

            if (mfa.RememberMe?.Enabled == true)
                factors.Add(new SecondFactor(MfaMethod.RememberMeToken));

            if (mfa.WebAuthn?.Enabled == true)
                factors.Add(new SecondFactor(MfaMethod.WebAuthn, mfa.WebAuthn));

            if (mfa.Duo?.Enabled == true)
                factors.Add(new SecondFactor(MfaMethod.Duo, mfa.Duo));

            if (factors.Count == 0)
                throw new InternalErrorException("No supported 2FA methods found");

            return factors.ToArray();
        }

        internal static async Task<OneOf<MfaSuccess, MfaRetry>> PerformSecondFactorAuthentication(
            int attempt,
            SecondFactor[] factors,
            Credentials credentials,
            AesKey sessionKey,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // Try "remember me" first. It's possible the server didn't allow it, or
            // we don't have a valid token stored from one of the previous sessions.
            var rememberMeResult = await TrySubmitRememberMeToken(factors, sessionKey, storage, rest, cancellationToken).ConfigureAwait(false);
            switch (rememberMeResult)
            {
                // Remember-me token was accepted, we're done.
                case RememberMeResult.Success:
                    return new MfaSuccess();

                // Remember-me token got rejected by the server, we need to restart the whole login sequence.
                case RememberMeResult.Rejected:
                    return new MfaRetry();

                // No remember-me token available, proceed with the interactive 2FA.
                case RememberMeResult.NotAvailable:
                    break;

                default:
                    throw new InternalErrorException("Invalid remember-me result");
            }

            // Figure out the initial 2FA method to use. The user might choose a different one later.
            var factor = ChooseInteractiveSecondFactor(factors);

            // Allow the user to change this as many times as they want until they cancel. Each method has only 3 attempts though.
            while (true)
            {
                var otherFactors = factors.Select(x => x.Method).Except([factor.Method, MfaMethod.RememberMeToken]).ToArray();

                // Ask the user to perform the 2FA step
                var result = await GetSecondFactorResult(attempt, factor, otherFactors, credentials, ui, rest, cancellationToken)
                    .ConfigureAwait(false);

                switch (result.Value)
                {
                    case SecondFactorResult secondFactorResult:
                        var token = await SubmitSecondFactorResult(factor.Method, secondFactorResult, sessionKey, rest, cancellationToken)
                            .ConfigureAwait(false);

                        // Store the token with the application. Next time we're not going to need to enter any passcodes.
                        if (secondFactorResult.RememberMe)
                            await storage.StoreString(RememberMeTokenKey, token).ConfigureAwait(false);

                        return new MfaSuccess();

                    case MfaMethod mfaMethod:
                        if (!otherFactors.Contains(mfaMethod))
                            throw new InternalErrorException("The UI chose an invalid MFA method");

                        factor = factors.First(x => x.Method == mfaMethod);
                        continue;

                    case Canceled:
                        throw new CanceledMultiFactorException("Second factor step is canceled by the user");
                }
            }
        }

        internal enum RememberMeResult
        {
            Success,
            NotAvailable,
            Rejected,
        }

        internal static async Task<RememberMeResult> TrySubmitRememberMeToken(
            SecondFactor[] factors,
            AesKey sessionKey,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            if (factors.All(x => x.Method != MfaMethod.RememberMeToken))
                return RememberMeResult.NotAvailable;

            var token = await storage.LoadString(RememberMeTokenKey).ConfigureAwait(false);
            if (string.IsNullOrEmpty(token))
                return RememberMeResult.NotAvailable;

            var result = new SecondFactorResult(
                Parameters: new Dictionary<string, string> { ["dshmac"] = Util.HashRememberMeToken(token, sessionKey.Id) },
                RememberMe: true
            );

            try
            {
                await SubmitSecondFactorResult(MfaMethod.RememberMeToken, result, sessionKey, rest, cancellationToken).ConfigureAwait(false);
                return RememberMeResult.Success;
            }
            catch (BadMultiFactorException)
            {
                // The token got rejected, need to erase it, it's no longer valid.
                await storage.StoreString(RememberMeTokenKey, null).ConfigureAwait(false);

                // When the stored 'remember me' token is rejected by the server, we need to try
                // the whole login sequence one more time. Probably the token is expired or it's
                // invalid.
                return RememberMeResult.Rejected;
            }
        }

        internal static SecondFactor ChooseInteractiveSecondFactor(SecondFactor[] factors)
        {
            if (factors.Length == 0)
                throw new InternalErrorException("The list of 2FA methods is empty");

            // We have O(N^2) here, but it's ok, since it's at most just a handful of elements.
            // Converting them to a hash set would take longer.
            foreach (var i in SecondFactorPriority)
            foreach (var f in factors)
                if (f.Method == i)
                    return f;

            throw new InternalErrorException("The list of 2FA methods doesn't contain any supported methods");
        }

        internal record SecondFactorResult(Dictionary<string, string> Parameters, bool RememberMe, string Note = "");

        internal static async Task<OneOf<SecondFactorResult, MfaMethod, Canceled>> GetSecondFactorResult(
            int attempt,
            SecondFactor factor,
            MfaMethod[] otherFactors,
            Credentials credentials,
            IAsyncUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            return factor.Method switch
            {
                MfaMethod.GoogleAuthenticator => await AuthenticateWithGoogleAuth(attempt, otherFactors, ui, cancellationToken).ConfigureAwait(false),
                MfaMethod.WebAuthn => await AuthenticateWithWebAuthn(attempt, factor, otherFactors, credentials, ui, cancellationToken)
                    .ConfigureAwait(false),
                MfaMethod.Duo => await AuthenticateWithDuo(factor, otherFactors, ui, rest, cancellationToken).ConfigureAwait(false),
                _ => throw new InternalErrorException($"2FA method {factor.Method} is not valid here"),
            };
        }

        internal static async Task<OneOf<SecondFactorResult, MfaMethod, Canceled>> AuthenticateWithGoogleAuth(
            int attempt,
            MfaMethod[] otherFactors,
            IAsyncUi ui,
            CancellationToken cancellationToken
        )
        {
            var otpResult = await ui.ProvideGoogleAuthPasscode(attempt, otherFactors, cancellationToken).ConfigureAwait(false);
            return otpResult.MapT0(otp => new SecondFactorResult(new Dictionary<string, string> { ["code"] = otp.Passcode }, otp.RememberMe));
        }

        internal static async Task<OneOf<SecondFactorResult, MfaMethod, Canceled>> AuthenticateWithWebAuthn(
            int attempt,
            SecondFactor factor,
            MfaMethod[] otherFactors,
            Credentials credentials,
            IAsyncUi ui,
            CancellationToken cancellationToken
        )
        {
            var rememberMeResult = await ui.ProvideWebAuthnRememberMe(attempt, otherFactors, cancellationToken).ConfigureAwait(false);
            var rememberMe = false;

            switch (rememberMeResult.Value)
            {
                case RememberMe rm:
                    rememberMe = rm.Value;
                    break;
                case MfaMethod mfaMethod:
                    return mfaMethod;
                case Canceled canceled:
                    return canceled;
            }

            if (factor.Parameters is not Model.WebAuthnMfa extra)
                throw new InternalErrorException("WebAuthn extra parameters expected");

            if (extra.KeyHandles?.Length == 0)
                throw new InternalErrorException("Expected at least one WebAuthn key to be provided");

            try
            {
                var assertion = WebAuthN.GetAssertion(
                    appId: Validate(extra.RpId, "rpid"),
                    challenge: Validate(extra.Challenge, "challenge"),
                    origin: $"https://{credentials.Domain}",
                    crossOrigin: false,
                    keyHandles: extra.KeyHandles
                );

                return new SecondFactorResult(
                    new Dictionary<string, string>
                    {
                        ["keyHandle"] = assertion.KeyHandle,
                        ["signature"] = assertion.Signature,
                        ["authData"] = assertion.AuthData,
                        ["clientData"] = assertion.ClientData,
                    },
                    rememberMe
                );
            }
            catch (CanceledException)
            {
                return new Canceled("User canceled WebAuthn authentication");
            }
            catch (ErrorException e)
            {
                throw new InternalErrorException("WebAuthn authentication failed", e);
            }

            // ---

            static string Validate(string? param, string name) =>
                param.IsNullOrEmpty() ? throw new InternalErrorException($"WebAuthn '{name}' is invalid") : param;
        }

        internal static async Task<OneOf<SecondFactorResult, MfaMethod, Canceled>> AuthenticateWithDuo(
            SecondFactor factor,
            MfaMethod[] otherFactors,
            IAsyncUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            if (factor.Parameters is not Model.DuoMfa extra)
                throw new InternalErrorException("Duo extra parameters expected");

            var isV1 = extra.Url.IsNullOrEmpty();
            var result = isV1
                ? await DuoV1
                    .AuthenticateAsync(
                        CheckParam(extra.Host, "host"),
                        CheckParam(extra.Signature, "sigRequest"),
                        otherFactors,
                        ui,
                        rest.Transport,
                        logger: null,
                        cancellationToken
                    )
                    .ConfigureAwait(false)
                : await DuoV4.AuthenticateAsync(extra.Url, otherFactors, ui, rest.Transport, logger: null, cancellationToken).ConfigureAwait(false);

            return result.Match<OneOf<SecondFactorResult, MfaMethod, Canceled>>(
                duoResult =>
                {
                    var key = isV1 ? "sigResponse" : "code";
                    var note = isV1 ? "v1" : "v4";
                    return new SecondFactorResult(
                        Parameters: new Dictionary<string, string> { [key] = duoResult.Code },
                        RememberMe: duoResult.RememberMe,
                        Note: note
                    );
                },
                mfaMethod => mfaMethod,
                duoCancelled => new Canceled(duoCancelled.Reason)
            );

            // ---

            static string CheckParam(string param, string name)
            {
                if (param.IsNullOrEmpty())
                    throw new InternalErrorException($"Duo parameter '{name}' is invalid");

                return param;
            }
        }

        // Returns "remember me" token when successful
        internal static async Task<string> SubmitSecondFactorResult(
            MfaMethod factor,
            SecondFactorResult result,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var key = factor switch
            {
                MfaMethod.GoogleAuthenticator => "totp",
                MfaMethod.RememberMeToken => "dsecret",
                MfaMethod.WebAuthn => "webAuthn",
                MfaMethod.Duo => result.Note switch
                {
                    "v1" => "duo",
                    "v4" => "duov4",
                    _ => throw new InternalErrorException($"Invalid Duo version '{result.Note}'"),
                },
                _ => throw new InternalErrorException($"2FA method {factor} is not valid"),
            };

            try
            {
                var response = await PostEncryptedJson<Model.Mfa>(
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
                    )
                    .ConfigureAwait(false);

                return response.RememberMeToken;
            }
            catch (BadCredentialsException e)
            {
                // The server report everything as "no auth" error. In this case we know it's related to the MFA.
                throw new BadMultiFactorException("Incorrect second factor code", e);
            }
        }

        // TODO: Rename to RequestAccountInfo
        internal static async Task<Model.AccountInfo> GetAccountInfo(AesKey sessionKey, RestClient rest, CancellationToken cancellationToken)
        {
            return await GetEncryptedJson<Model.AccountInfo>(
                    "v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults",
                    sessionKey,
                    rest,
                    cancellationToken
                )
                .ConfigureAwait(false);
        }

        // TODO: Rename to RequestKeysets
        internal static async Task<Model.KeysetsInfo> GetKeysets(AesKey sessionKey, RestClient rest, CancellationToken cancellationToken)
        {
            return await GetEncryptedJson<Model.KeysetsInfo>("v1/account/keysets", sessionKey, rest, cancellationToken).ConfigureAwait(false);
        }

        // TODO: We don't really need IEnumerable here
        internal static IEnumerable<VaultInfo> GetAccessibleVaults(Model.AccountInfo accountInfo, Keychain keychain)
        {
            return from vault in accountInfo.Vaults
                let key = FindWorkingKey(vault.Access, keychain)
                where key != null
                select new VaultInfo(vault.Id, Encrypted.Parse(vault.Attributes), key, keychain);
        }

        internal static Encrypted FindWorkingKey(Model.VaultAccessInfo[] accessList, Keychain keychain)
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

            await foreach (var item in EnumerateAccountsItemsInVault(id, sessionKey, rest, cancellationToken).ConfigureAwait(false))
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

        internal static OneOf<Account, SshKey, NoItem> ConvertVaultItem(Keychain keychain, Model.VaultItem item)
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
            var response = await rest.GetAsync<Model.Encrypted>($"v1/vault/{vaultId}/item/{itemId}", cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return ConvertVaultItem(keychain, DecryptResponse<Model.SingleVaultItem>(response.Data, sessionKey).Item);

            var error = MakeError(response);
            return error switch
            {
                // Special case: the item not found
                NotFoundException => NoItem.NotFound,
                _ => throw error,
            };
        }

        // TODO: Rename to RequestVaultAccounts? It should clearer from the name that it's a slow operation.
        // Don't enumerate more than once. It's very slow since it makes network requests.
        internal static async IAsyncEnumerable<Model.VaultItem> EnumerateAccountsItemsInVault(
            string id,
            AesKey sessionKey,
            RestClient rest,
            [EnumeratorCancellation] CancellationToken cancellationToken
        )
        {
            var batchId = 0;
            while (true)
            {
                var batch = await GetEncryptedJson<Model.VaultItemsBatch>($"v1/vault/{id}/{batchId}/items", sessionKey, rest, cancellationToken)
                    .ConfigureAwait(false);
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
            var response = await rest.PutAsync<Model.SuccessStatus>("v1/session/signout", cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw MakeError(response);

            if (response.Data.Success != 1)
                throw new InternalErrorException("Failed to logout");
        }

        internal static void DecryptKeysets(Model.KeysetInfo[] keysets, Credentials credentials, Keychain keychain)
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
            var encryptsKeysets = new Dictionary<string, List<Model.KeysetInfo>>();
            foreach (var keyset in keysets)
                encryptsKeysets.GetOrAdd(GetEncryptedBy(keyset), () => new List<Model.KeysetInfo>()).Add(keyset);

            // Start from "mp" and topologically walk the keys in a valid decryption order
            var queue = new Queue<Model.KeysetInfo>(encryptsKeysets[MasterKeyId]);
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

        internal static string GetEncryptedBy(Model.KeysetInfo keyset)
        {
            return keyset.EncryptedBy.IsNullOrEmpty() ? keyset.KeyOrMasterKey.KeyId : keyset.EncryptedBy;
        }

        internal static void DecryptKeyset(Model.KeysetInfo keyset, Keychain keychain)
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
        // Error handling
        //

        internal class NotFoundException(string message) : BaseException(message);

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
                var error = JsonSerializer.Deserialize<Model.Error>(response);
                switch (error.Code)
                {
                    case 102:
                        return new BadCredentialsException("Username, password or account key is incorrect");
                    case 117:
                        return new NotFoundException($"The requested item not found: '{error.Message}'");
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
                var reason = JsonSerializer.Deserialize<Model.FailureReason>(response).Reason;
                if (!reason.IsNullOrEmpty())
                    return new InternalErrorException($"The server responded with the failure reason: '{reason}'");
            }
            catch (JsonException)
            {
                // Ignore, it wasn't a server error
            }

            return null;
        }

        //
        // Network
        //

        internal static async Task<T> GetEncryptedJson<T>(string endpoint, AesKey sessionKey, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.GetAsync<Model.Encrypted>(endpoint, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return DecryptResponse<T>(response.Data, sessionKey);
        }

        internal static async Task<T> PostEncryptedJson<T>(
            string endpoint,
            Dictionary<string, object> parameters,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var encrypted = await PostEncryptedJsonNoDecrypt<Model.Encrypted>(endpoint, parameters, sessionKey, rest, cancellationToken)
                .ConfigureAwait(false);
            return DecryptResponse<T>(encrypted, sessionKey);
        }

        internal static async Task<T> PostEncryptedJsonNoDecrypt<T>(
            string endpoint,
            Dictionary<string, object> parameters,
            AesKey sessionKey,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var payload = JsonSerializer.Serialize(parameters);
            var encryptedPayload = sessionKey.Encrypt(payload.ToBytes());

            var response = await rest.PostJsonAsync<T>(endpoint, encryptedPayload.ToDictionary(), cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data;
        }

        internal static T DecryptResponse<T>(Model.Encrypted encrypted, IDecryptor decryptor)
        {
            var plaintext = decryptor.Decrypt(Encrypted.Parse(encrypted)).ToUtf8();

            // First check for server errors. It's possible to deserialize the returned error object
            // into one of the target types by mistake when the type has no mandatory fields.
            // `Model.Mfa` would be one of those.
            if (ParseServerError(plaintext) is { } serverError)
                throw serverError;

            try
            {
                return JsonSerializer.Deserialize<T>(plaintext);
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

        private static MfaMethod[] SecondFactorPriority =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? SecondFactorPriorityWindows : SecondFactorPriorityOtherPlatforms;

        private static readonly MfaMethod[] SecondFactorPriorityWindows = [MfaMethod.WebAuthn, MfaMethod.Duo, MfaMethod.GoogleAuthenticator];

        private static readonly MfaMethod[] SecondFactorPriorityOtherPlatforms = [MfaMethod.Duo, MfaMethod.GoogleAuthenticator];
    }
}
