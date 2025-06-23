// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ProtonPass.Protobuf;
using PgpCore;
using RestSharp;
using RestSharp.Authenticators.OAuth2;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Client
    {
        // TODO: Refactor this function once done with the logic!
        public static async Task<Vault[]> OpenAll(
            string username,
            string password,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestAsync.Config config,
            CancellationToken cancellationToken
        )
        {
            var rest = RestAsync.Create(BaseUrl, config);
            rest.AddOrUpdateDefaultHeader("X-Pm-Appversion", AppVersion);

            // For the network traffic analysis it seems that there are two different access tokens. The first one
            // is just for requesting the auth info and initiating the login session. After that is done and identity
            // is verified, the second access token is issued. The first one is not used anymore. The second one is
            // used to get the actual vault data.

            // Load the previous session
            var sessionId = await storage.LoadString("session-id").ConfigureAwait(false);
            var accessToken = await storage.LoadString("access-token").ConfigureAwait(false);
            var refreshToken = await storage.LoadString("refresh-token").ConfigureAwait(false);
            var humanVerificationTokenType = await storage.LoadString("human-verification-token-type").ConfigureAwait(false);
            var humanVerificationToken = await storage.LoadString("human-verification-token").ConfigureAwait(false);

            // TODO: Do we need to store this and use it again the next time?
            if (!humanVerificationTokenType.IsNullOrEmpty() && !humanVerificationToken.IsNullOrEmpty())
            {
                rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token-Type", humanVerificationTokenType!);
                rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token", humanVerificationToken!);
            }

            // Either it's the first time we're running or the storage is corrupted. We need to start from scratch.
            if (sessionId.IsNullOrEmpty() || accessToken.IsNullOrEmpty() || refreshToken.IsNullOrEmpty())
            {
                // Get a fresh set of access tokens: access and refresh.
                await FullLoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                // We have a session ID and the access token. Let's try to use them to access the vault.
                rest.AddOrUpdateDefaultHeader("X-Pm-Uid", sessionId!);
                rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(accessToken!, "Bearer"));
            }

            // The flow could go through the following steps:
            // 1. The access token expired. We need to refresh it and try again.
            // 2. 2FA is needed. We need to provide the 2FA passcode and try again.
            // 3. The extra password is needed. We need to provide it and try again.
            // 4. Download the vault.

            // It's impossible to predict how many steps we need to go through exactly.
            // Instead, we allow each of the following exceptions to happen only once.
            // If they happen more than once that means there is some logic error in
            // the client or the server is misbehaving.
            var hadTokenExpired = false;
            var hadLockedScope = false;
            var hadPassScope = false;
            var errorDetails = "";

            while (true)
            {
                try
                {
                    return await DownloadAllVaults(password, rest, cancellationToken).ConfigureAwait(false);
                }
                catch (TokenExpiredException)
                {
                    if (hadTokenExpired)
                    {
                        errorDetails = "multiple token expired exceptions";
                        break;
                    }

                    hadTokenExpired = true;

                    if (
                        refreshToken.IsNullOrEmpty()
                        || !await TryRefreshAuthSessionAndUpdate(sessionId!, refreshToken!, storage, rest, cancellationToken).ConfigureAwait(false)
                    )
                    {
                        // The refresh token is expired. We need to do a full login.
                        await FullLoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (MissingLockedScopeException)
                {
                    if (hadLockedScope)
                    {
                        errorDetails = "multiple missing locked scope exceptions";
                        break;
                    }

                    hadLockedScope = true;

                    // We already have a session, so we don't need a full login, only the SRP part.
                    await LoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                }
                catch (MissingPassScopeException)
                {
                    if (hadPassScope)
                    {
                        errorDetails = "multiple missing pass scope exceptions";
                        break;
                    }

                    hadPassScope = true;

                    // The pass scope is missing. This means we need to provide the extra password.
                    await DoAuthWithExtraPassword(username, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                }
            }

            throw new InternalErrorException($"Failed to download the vault: {errorDetails}");
        }

        //
        // Internal
        //

        // This function is full of side effects. It modifies the REST client, the storage and the UI.
        internal static async Task FullLoginAndUpdate(
            string username,
            string password,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            await GetBasicSessionAndUpdate(storage, rest, cancellationToken).ConfigureAwait(false);
            await LoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
        }

        // This function is full of side effects. It modifies the REST client and the storage.
        internal static async Task GetBasicSessionAndUpdate(IAsyncSecureStorage storage, RestClient rest, CancellationToken cancellationToken)
        {
            // To request this session we don't need any authentication. This session is only good for requesting the auth info.
            var session = await RequestNewAuthSession(rest, cancellationToken).ConfigureAwait(false);

            // We save the session ID only. The access and the refresh tokens are only good for requesting
            // the auth info at this point. They don't give any other access. We save them after
            // the authorization is granted. The rest we erase.
            await StoreSession(session.Id, null, null, storage).ConfigureAwait(false);

            // Update the REST
            rest.AddOrUpdateDefaultHeader("X-Pm-Uid", session.Id);
            rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(session.AccessToken, "Bearer"));
        }

        // This function is full of side effects. It modifies the REST client, the storage and the UI.
        // The REST is expected to be configured with a basic session at this point.
        internal static async Task LoginAndUpdate(
            string username,
            string password,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // 1. Request the auth info that contains the SRP challenge and related data.
            var authInfo = await RequestAuthInfo(username, rest, cancellationToken).ConfigureAwait(false);

            // 2. Generate the SRP challenge response.
            var proof = Srp.GenerateProofs(
                version: authInfo.Version,
                password: password,
                username: username,
                saltBytes: authInfo.Salt.Decode64(),
                serverEphemeralBytes: authInfo.ServerEphemeral.Decode64(),
                modulusBytes: Srp.ParseModulus(authInfo.Modulus)
            );

            // TODO: How many attempts do we need here? Do we need more than 2?
            for (var attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    // 3. Submit the SRP proof to the server. At this point we could get the CAPTCHA challenge.
                    var auth = await SubmitSrpProof(username, authInfo.SrpSession, proof, rest, cancellationToken).ConfigureAwait(false);

                    // Update the RestClient
                    rest.AddOrUpdateDefaultHeader("X-Pm-Uid", auth.SessionId);
                    rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(auth.AccessToken, "Bearer"));

                    // 4. Check if we need to provide 2FA
                    if (auth.Mfa.Enabled != 0)
                    {
                        await DoMultiFactorAuth(auth.Mfa, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                    }

                    // Once the auth has been granted, the tokens returned by the server give full access to the vault.
                    // They need to be saved for the next sessions.
                    await StoreSession(auth.SessionId, auth.AccessToken, auth.RefreshToken, storage).ConfigureAwait(false);
                    return;
                }
                catch (NeedCaptchaException e)
                {
                    // Wipe the old HV token, it clearly didn't work
                    await StoreHumanVerificationToken(null, null, storage).ConfigureAwait(false);

                    // TODO: Support other types of human verification
                    var result = await ui.SolveCaptcha(e.Url, e.HumanVerificationToken, cancellationToken).ConfigureAwait(false);

                    // Explicitly cancelled
                    if (result == IAsyncUi.CaptchaResult.Cancel)
                        throw new CanceledMultiFactorException("CAPTCHA verification cancelled by the user");

                    // Failed or something went wrong
                    if (!result.Solved)
                        throw new InternalErrorException("CAPTCHA verification failed");

                    rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token-Type", "captcha");
                    rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token", result.Token);

                    await StoreHumanVerificationToken("captcha", result.Token, storage).ConfigureAwait(false);
                }
            }
        }

        private static async Task DoMultiFactorAuth(
            Model.Mfa mfa,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // TODO: Allow the user to choose the 2FA method when there are multiple enabled

            if ((mfa.Enabled & MfaGoogleAuthEnabled) != 0)
            {
                await DoTotpMultiFactorAuth(mfa, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                return;
            }

            if ((mfa.Enabled & MfaFido2Enabled) != 0)
            {
                await DoFido2MultiFactorAuth(mfa, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                return;
            }

            throw new InternalErrorException($"Unknown 2FA method {mfa.Enabled}");
        }

        private static async Task DoTotpMultiFactorAuth(
            Model.Mfa mfa,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            for (var attempt = 0; attempt < MaxGoogleAuthAttempts; attempt++)
            {
                var result = await ui.ProvideGoogleAuthPasscode(attempt, cancellationToken).ConfigureAwait(false);
                if (result == IAsyncUi.PasscodeResult.Cancel)
                    throw new CanceledMultiFactorException("Google Authenticator 2FA step cancelled by the user");

                var request = new RestRequest("auth/v4/2fa").AddJsonBody(new { TwoFactorCode = result.Passcode });

                var response = await rest.ExecutePostAsync<Model.Response>(request, cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessful)
                    return;

                var error = MakeError(response);
                if (error is BadCredentialsException)
                {
                    if (attempt == MaxGoogleAuthAttempts - 1)
                        throw new BadMultiFactorException("Too many failed attempts to provide the Google Authenticator passcode");
                }
                else
                {
                    throw error;
                }
            }
        }

        private static Task DoFido2MultiFactorAuth(
            Model.Mfa mfa,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            throw new UnsupportedFeatureException($"FIDO2 2FA is not supported yet");
        }

        internal static async Task DoAuthWithExtraPassword(
            string username,
            IAsyncUi ui,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // TODO: Add cancellation token checks!
            for (var attempt = 0; attempt < MaxExtraPasswordAttempts; attempt++)
            {
                // 1. Get the extra password from the user
                var extraPassword = await ui.ProvideExtraPassword(attempt, cancellationToken).ConfigureAwait(false);
                if (extraPassword == IAsyncUi.PasscodeResult.Cancel)
                    throw new CanceledMultiFactorException("The extra password step cancelled by the user");

                // 2. Request the auth info that contains the SRP challenge and related data
                var srpData = await RequestExtraAuthInfo(username, rest, cancellationToken).ConfigureAwait(false);

                // 3. Generate the SRP challenge response
                var proof = Srp.GenerateProofs(
                    version: srpData.Version,
                    password: extraPassword.Passcode,
                    username: username,
                    saltBytes: srpData.Salt.Decode64(),
                    serverEphemeralBytes: srpData.ServerEphemeral.Decode64(),
                    modulusBytes: Srp.ParseModulus(srpData.Modulus)
                );

                // 4. Submit the SRP proof to the server
                try
                {
                    await SubmitExtraSrpProof(srpData.SessionId, proof, rest, cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (InvalidExtraPasswordException)
                {
                    // Do nothing, retry.
                }
                catch (TooManyInvalidExtraPasswordAttemptsException)
                {
                    break;
                }
            }

            throw new BadMultiFactorException("Too many failed attempts to provide the extra password");
        }

        // This function is full of side effects. It modifies the rest client and the storage.
        internal static async Task<bool> TryRefreshAuthSessionAndUpdate(
            string sessionId,
            string refreshToken,
            IAsyncSecureStorage storage,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            try
            {
                var session = await RefreshAuthSession(sessionId, refreshToken, rest, cancellationToken).ConfigureAwait(false);

                // Update the RestClient
                rest.AddOrUpdateDefaultHeader("X-Pm-Uid", session.Id);
                rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(session.AccessToken, "Bearer"));

                // Save for the next session
                await StoreSession(session.Id, session.AccessToken, session.RefreshToken, storage).ConfigureAwait(false);

                return true;
            }
            catch (TokenExpiredException)
            {
                // The refresh token is expired as well. Erase everything and start from scratch.
                await StoreSession(sessionId, null, null, storage).ConfigureAwait(false);

                return false;
            }
        }

        internal static async Task StoreSession(string? sessionId, string? accessToken, string? refreshToken, IAsyncSecureStorage storage)
        {
            await storage.StoreString("session-id", sessionId).ConfigureAwait(false);
            await storage.StoreString("access-token", accessToken).ConfigureAwait(false);
            await storage.StoreString("refresh-token", refreshToken).ConfigureAwait(false);
        }

        internal static async Task StoreHumanVerificationToken(string? tokenType, string? token, IAsyncSecureStorage storage)
        {
            await storage.StoreString("human-verification-token-type", tokenType).ConfigureAwait(false);
            await storage.StoreString("human-verification-token", token).ConfigureAwait(false);
        }

        internal static async Task<Model.Session> RequestNewAuthSession(RestClient rest, CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4/sessions");
            var response = await rest.ExecutePostAsync<Model.Session>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static async Task<Model.Session> RefreshAuthSession(
            string sessionId,
            string refreshToken,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var request = new RestRequest("auth/v4/refresh").AddJsonBody(
                new
                {
                    UID = sessionId,
                    RefreshToken = refreshToken,
                    ResponseType = "token",
                    GrantType = "refresh_token",
                    RedirectURI = "http://protonmail.ch",
                }
            );

            var response = await rest.ExecutePostAsync<Model.Session>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static async Task<Model.AuthInfo> RequestAuthInfo(string username, RestClient rest, CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4/info").AddJsonBody(new { Username = username, Intent = "Proton" });

            var response = await rest.ExecutePostAsync<Model.AuthInfo>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static async Task<Model.SrpData> RequestExtraAuthInfo(string username, RestClient rest, CancellationToken cancellationToken)
        {
            var request = new RestRequest("pass/v1/user/srp/info").AddJsonBody(new { Username = username, Intent = "Proton" });

            var response = await rest.ExecuteGetAsync<Model.ExtraAuthInfo>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!.SrpData;
        }

        private static async Task<Model.Auth> SubmitSrpProof(
            string username,
            string srpSession,
            Srp.Proofs proof,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var request = new RestRequest("auth/v4").AddJsonBody(
                new
                {
                    Username = username,
                    ClientEphemeral = proof.ClientEphemeral.ToBase64(),
                    ClientProof = proof.ClientProof.ToBase64(),
                    SRPSession = srpSession,
                }
            );

            var response = await rest.ExecutePostAsync<Model.Auth>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        private static async Task SubmitExtraSrpProof(string srpSession, Srp.Proofs proof, RestClient rest, CancellationToken cancellationToken)
        {
            var request = new RestRequest("pass/v1/user/srp/auth").AddJsonBody(
                new
                {
                    ClientEphemeral = proof.ClientEphemeral.ToBase64(),
                    ClientProof = proof.ClientProof.ToBase64(),
                    SrpSessionID = srpSession,
                }
            );

            var response = await rest.ExecutePostAsync<Model.Response>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);
        }

        internal static async Task<Vault[]> DownloadAllVaults(string password, RestClient rest, CancellationToken cancellationToken)
        {
            // 1. Get the key salts
            // At this point we're very likely to fail, so we do this first. It seems that when an access token is a bit old and is still good
            // for downloading some of the data, it's not good enough to get the salts. We need a fresh one.
            var salts = await RequestKeySalts(rest, cancellationToken);

            // 2. Get the user info that contains the user keys
            var primaryKey = await RequestUserPrimaryKey(rest, cancellationToken);

            // 3. Derive the key passphrase
            // The salt seems to be optional in case of the older accounts. Not sure how to test this IRL.
            // When there's no salt, the master password is the key password.
            var keyPassphrase = DeriveKeyPassphrase(password, salts.FirstOrDefault(x => x.Id == primaryKey.Id)?.Salt);

            // 4. Get all vault shares info
            var vaultShares = await RequestAllVaultShares(rest, cancellationToken);
            if (vaultShares.Length == 0)
                throw new InternalErrorException("Expected at least one share");

            // 5. Initiate the parallel downloads
            var downloads = vaultShares.Select(share => DownloadVaultContent(share, primaryKey, keyPassphrase, rest, cancellationToken)).ToArray();

            // 6. Wait for all the downloads to finish
            return await Task.WhenAll(downloads).ConfigureAwait(false);
        }

        private static async Task<Vault> DownloadVaultContent(
            Model.Share vaultShare,
            Model.UserKey primaryKey,
            string keyPassphrase,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            // 1. Get the keys for the share
            var latestShareKey = await RequestShareKey(vaultShare, rest, cancellationToken);

            // 2. Make sure the user has a matching key
            if (latestShareKey.UserKeyId != primaryKey.Id)
                throw new InternalErrorException($"Share {vaultShare.Id} key {latestShareKey.UserKeyId} that doesn't match the user primary key");

            // 3. Decrypt the share key
            var vaultKey = await DecryptMessage(latestShareKey.Key, primaryKey.PrivateKey, keyPassphrase).ConfigureAwait(false);

            // 4. Decrypt vault info
            var vaultInfo = DecryptVaultInfo(vaultShare, vaultKey);

            var accounts = new List<Account>();
            var nextBatchMarker = "";

            // 5. Get all the vault items in batches
            do
            {
                // One batch at a time
                nextBatchMarker = await GetVaultNextItems(vaultShare.Id, vaultKey, nextBatchMarker, accounts, rest, cancellationToken)
                    .ConfigureAwait(false);
            } while (nextBatchMarker != "");

            // 6. Done
            return new Vault
            {
                Id = vaultShare.Id, // TODO: Should we use VaultId instead? What's the difference?
                Name = vaultInfo.Name,
                Description = vaultInfo.Description,
                Accounts = accounts.ToArray(),
            };
        }

        internal static async Task<Model.KeySalt[]> RequestKeySalts(RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.ExecuteGetAsync<Model.SaltsResponse>(new RestRequest("core/v4/keys/salts"), cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!.KeySalts;
        }

        internal static async Task<Model.UserKey> RequestUserPrimaryKey(RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.ExecuteGetAsync<Model.UserResponse>(new RestRequest("core/v4/users"), cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            var user = response.Data!.User;
            if (user.Keys.Length == 0)
                throw new InternalErrorException("Expected at least one user key");

            var primaryKey = user.Keys.FirstOrDefault(x => x.Primary == 1);
            if (primaryKey == null)
                throw new InternalErrorException("Expected a primary key");

            return primaryKey;
        }

        internal static async Task<Model.Share[]> RequestAllVaultShares(RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.ExecuteGetAsync<Model.ShareRoot>(new RestRequest("pass/v1/share"), cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw MakeError(response);

            var shares = response.Data!.Shares;

            // Filter out only the vault shares
            return shares.Where(x => x.TargetType == 1).ToArray();
        }

        internal static async Task<Model.ShareKey> RequestShareKey(Model.Share vaultShare, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.ExecuteGetAsync<Model.ShareKeysRoot>(new RestRequest($"pass/v1/share/{vaultShare.Id}/key"), cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessful)
                throw MakeError(response);

            var shareKeys = response.Data!.ShareKeys.Keys;
            if (shareKeys.Length == 0)
                throw new InternalErrorException("Expected at least one share key");

            // Find the latest key
            var latestShareKey = shareKeys.MaxBy(x => x.KeyRotation);
            if (latestShareKey == null)
                throw new InternalErrorException("Expected at least one share key");

            return latestShareKey;
        }

        internal static Protobuf.Vault DecryptVaultInfo(Model.Share vaultShare, byte[] vaultKey)
        {
            // The content is encoded with Protobuf and then encrypted with AES-GCM
            var encryptedShareInfo = vaultShare.Content.Decode64();
            var shareInfoProto = OnePassword.AesGcm.Decrypt(
                key: vaultKey,
                ciphertext: encryptedShareInfo.Sub(12, encryptedShareInfo.Length - 12),
                iv: encryptedShareInfo.Sub(0, 12),
                adata: "vaultcontent".ToBytes()
            );
            return Protobuf.Vault.Parser.ParseFrom(shareInfoProto);
        }

        // Appends the account to the list and returns the next batch marker
        internal static async Task<string> GetVaultNextItems(
            string shareId,
            byte[] vaultKey,
            string nextBatchMarker,
            List<Account> accounts,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var url = $"pass/v1/share/{shareId}/item";
            if (nextBatchMarker != "")
                url += $"?Since={nextBatchMarker}";

            var r3 = await rest.ExecuteGetAsync<Model.VaultResponse>(new RestRequest(url), cancellationToken).ConfigureAwait(false);
            if (!r3.IsSuccessful)
                throw MakeError(r3);

            var vault = r3.Data!.Items;

            // Reserve space
            accounts.Capacity = Math.Max(accounts.Capacity, accounts.Count + vault.Items.Length);

            foreach (var item in vault.Items)
            {
                // Skip trashed items
                if (item.State != ItemStateRegular)
                    continue;

                var encryptedKey = item.ItemKey.Decode64();
                var key = OnePassword.AesGcm.Decrypt(
                    key: vaultKey,
                    ciphertext: encryptedKey.Sub(12, encryptedKey.Length - 12),
                    iv: encryptedKey.Sub(0, 12),
                    adata: "itemkey".ToBytes()
                );

                var encryptedContent = item.Content.Decode64();
                var content = OnePassword.AesGcm.Decrypt(
                    key: key,
                    ciphertext: encryptedContent.Sub(12, encryptedContent.Length - 12),
                    iv: encryptedContent.Sub(0, 12),
                    adata: "itemcontent".ToBytes()
                );

                var parsedItem = Item.Parser.ParseFrom(content);

                if (parsedItem.Content.ContentCase != Content.ContentOneofCase.Login)
                    continue;

                var metadata = parsedItem.Metadata;
                var login = parsedItem.Content.Login;

                accounts.Add(
                    new Account
                    {
                        Id = item.Id ?? "",
                        Name = metadata.Name ?? "",
                        Email = login.ItemEmail ?? "",
                        Username = login.ItemUsername ?? "",
                        Password = login.Password ?? "",
                        Urls = login.Urls?.ToArray() ?? [],
                        Totp = login.TotpUri ?? "",
                        Note = metadata.Note,
                    }
                );
            }

            return vault.LastToken ?? "";
        }

        private static string DeriveKeyPassphrase(string password, string? saltBase64)
        {
            if (saltBase64.IsNullOrEmpty())
                return password;

            return DeriveKeyPassphrase(password, saltBase64.Decode64());
        }

        private static string DeriveKeyPassphrase(string password, byte[] salt)
        {
            return Srp.BCryptHashPassword(password, Srp.EncodeBase64(salt, 16)).Substring(29);
        }

        private static async Task<byte[]> DecryptMessage(string messageBase64, string privateKey, string passphrase)
        {
            return await DecryptMessage(messageBase64.Decode64(), privateKey, passphrase).ConfigureAwait(false);
        }

        private static async Task<byte[]> DecryptMessage(byte[] message, string privateKey, string passphrase)
        {
            using var pgp = new PGP(new EncryptionKeys(privateKey, passphrase));
            using var inputStream = new MemoryStream(message);
            using var outputStream = new MemoryStream();
            await pgp.DecryptAsync(inputStream, outputStream).ConfigureAwait(false);
            return outputStream.ToArray();
        }

        internal class TokenExpiredException() : BaseException("Access token expired");

        internal class MissingLockedScopeException() : BaseException("Missing locked scope");

        internal class MissingPassScopeException() : BaseException("Missing pass scope");

        internal class InvalidExtraPasswordException() : BaseException("Invalid extra password");

        internal class TooManyInvalidExtraPasswordAttemptsException() : BaseException("Too many invalid extra password attempts");

        internal class NeedCaptchaException(string url, string humanVerificationToken) : BaseException("CAPTCHA verification required")
        {
            public string Url { get; } = url;
            public string HumanVerificationToken { get; } = humanVerificationToken;
        }

        internal static BaseException MakeError<T>(RestSharp.RestResponse<T> response)
        {
            if (response.IsNetworkError())
                return new NetworkErrorException("Network error", response.ErrorException);

            if (!response.IsSuccessStatusCode)
            {
                // Try to parse the error object from the response
                var errorCode = 0;
                var errorText = "";
                if (RestAsync.TryDeserialize<Model.Error>(response.Content ?? "", out var error))
                {
                    errorCode = error!.Code;
                    errorText = error.Text ?? "";
                }

                return errorCode switch
                {
                    401 or 10013 => new TokenExpiredException(),
                    // TODO: Check what kind of other human verification methods are there
                    // TODO: Verify that the url and the token are set
                    9001 when HasHumanVerificationMethod(error, "captcha") => new NeedCaptchaException(
                        error!.Details!.Url!,
                        error.Details.HumanVerificationToken!
                    ),
                    8002 => new BadCredentialsException("Invalid credentials"),
                    // Handle "locked" first, in case there are both "locked" and "pass"
                    9101 when HasMissingScope(error, "locked") => new MissingLockedScopeException(),
                    9108 when HasMissingScope(error, "pass") => new MissingPassScopeException(),
                    2011 => new InvalidExtraPasswordException(),
                    2026 => new TooManyInvalidExtraPasswordAttemptsException(),
                    _ => new InternalErrorException(
                        $"Request to '{response.ResponseUri}' failed with HTTP status {response.StatusCode} and error {errorCode}: '{errorText}'"
                    ),
                };
            }

            if (response.IsJsonError())
                return new InternalErrorException("Failed to parse the response JSON", response.ErrorException);

            return new InternalErrorException($"Request to '{response.ResponseUri}' failed", response.ErrorException);
        }

        internal static bool HasHumanVerificationMethod(Model.Error? error, string method) =>
            error?.Details?.HumanVerificationMethods?.Contains(method) == true;

        internal static bool HasMissingScope(Model.Error? error, string scope) => error?.Details?.MissingScopes?.Contains(scope) == true;

        //
        // Data
        //

        // Android protocol
        internal const string BaseUrl = "https://pass-api.proton.me";
        internal const string AppVersion = "android-pass@1.27.1";

        internal const int MaxExtraPasswordAttempts = 3;
        internal const int ItemStateRegular = 1;

        internal const int MfaGoogleAuthEnabled = 1;
        internal const int MfaFido2Enabled = 2;

        internal const int MaxGoogleAuthAttempts = 3;
    }
}
