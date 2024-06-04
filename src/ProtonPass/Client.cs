// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PasswordManagerAccess.Common;
using PgpCore;
using RestSharp;
using RestSharp.Authenticators.OAuth2;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.ProtonPass
{
    // TODO: Move this out of here
    public interface IAsyncUi
    {
        public class Result
        {
            public bool Solved { get; set; }
            public string Token { get; set; } = "";
        }

        Task<Result> SolveCaptcha(string url, string humanVerificationToken, CancellationToken cancellationToken);
    }

    internal static class Client
    {
        // TODO: Refactor this function once done with the logic!
        public static async Task Open(string username,
                                      string password,
                                      IAsyncUi ui,
                                      IAsyncSecureStorage storage,
                                      RestAsync.Config config,
                                      CancellationToken cancellationToken)
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

            // Normally we have up to 3 login attempts. The worst case scenario is when:
            // 1. The access token expired. We need to refresh it and try again.
            // 2. The token is valid but the locked scope is missing. We need to do a full login.
            // 3. Download the vault.
            var maxAttempts = 3;

            // Either it's the first time we're running or the storage is corrupted. We need to start from scratch.
            if (sessionId.IsNullOrEmpty() || accessToken.IsNullOrEmpty() || refreshToken.IsNullOrEmpty())
            {
                await FullLoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);

               // We just got a fresh set of access tokens. There shouldn't be any failures at this point.
               maxAttempts = 1;
            }
            else
            {
                // We have a session ID and the access token. Let's try to use them to access the vault.
                rest.AddOrUpdateDefaultHeader("X-Pm-Uid", sessionId!);
                rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(accessToken!, "Bearer"));
            }

            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    await DownloadVault(password, rest, cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (TokenExpiredException)
                {
                    if (refreshToken.IsNullOrEmpty() ||
                        !await TryRefreshAuthSessionAndUpdate(sessionId!, refreshToken!, storage, rest, cancellationToken).ConfigureAwait(false))
                    {
                        // The refresh token is expired. We need to do a full login.
                        await FullLoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (MissingLockedScopeException)
                {
                    // We already have a session, so we don't need a full login, only the SRP part.
                    await LoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        //
        // Internal
        //

        // This function is full of side effects. It modifies the REST client, the storage and the UI.
        internal static async Task FullLoginAndUpdate(string username,
                                                      string password,
                                                      IAsyncUi ui,
                                                      IAsyncSecureStorage storage,
                                                      RestClient rest,
                                                      CancellationToken cancellationToken)
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
        internal static async Task LoginAndUpdate(string username,
                                                  string password,
                                                  IAsyncUi ui,
                                                  IAsyncSecureStorage storage,
                                                  RestClient rest,
                                                  CancellationToken cancellationToken)
        {
            // 1. Request the auth info that contains the SRP challenge and related data.
            var authInfo = await RequestAuthInfo(username, rest, cancellationToken).ConfigureAwait(false);

            // 2. Generate the SRP challenge response.
            var proof = Srp.GenerateProofs(version: authInfo.Version,
                                           password: password,
                                           username: username,
                                           saltBytes: authInfo.Salt.Decode64(),
                                           serverEphemeralBytes: authInfo.ServerEphemeral.Decode64(),
                                           modulusBytes: Srp.ParseModulus(authInfo.Modulus));

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
                    if (!result.Solved)
                        throw new InternalErrorException("CAPTCHA verification failed or was cancelled by the user");

                    rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token-Type", "captcha");
                    rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token", result.Token);

                    await StoreHumanVerificationToken("captcha", result.Token, storage).ConfigureAwait(false);
                }
            }
        }

        // This function is full of side effects. It modifies the rest client and the storage.
        internal static async Task<bool> TryRefreshAuthSessionAndUpdate(string sessionId,
                                                                        string refreshToken,
                                                                        IAsyncSecureStorage storage,
                                                                        RestClient rest,
                                                                        CancellationToken cancellationToken)
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



        internal static async Task StoreSession(string? sessionId,
                                                string? accessToken,
                                                string? refreshToken,
                                                IAsyncSecureStorage storage)
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

        internal static async Task<Model.Session> RefreshAuthSession(string sessionId,
                                                                     string refreshToken,
                                                                     RestClient rest,
                                                                     CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4/refresh")
                .AddJsonBody(new
                {
                    UID = sessionId,
                    RefreshToken = refreshToken,
                    ResponseType = "token",
                    GrantType = "refresh_token",
                    RedirectURI = "http://protonmail.ch",
                });

            var response = await rest.ExecutePostAsync<Model.Session>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static async Task<Model.AuthInfo> RequestAuthInfo(string username, RestClient rest, CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4/info")
                .AddJsonBody(new
                {
                    Username = username,
                    Intent = "Proton",
                });

            var response = await rest.ExecutePostAsync<Model.AuthInfo>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        private static async Task<Model.Auth> SubmitSrpProof(string username,
                                                             string srpSession,
                                                             Srp.Proofs proof,
                                                             RestClient rest,
                                                             CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4")
                .AddJsonBody(new
                {
                    Username = username,
                    ClientEphemeral = proof.ClientEphemeral.ToBase64(),
                    ClientProof = proof.ClientProof.ToBase64(),
                    SRPSession = srpSession,
                });

            var response = await rest.ExecutePostAsync<Model.Auth>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static async Task<string[]> DownloadVault(string password, RestClient rest, CancellationToken cancellationToken)
        {
            // 1. Get the key salts
            // At this point we're very likely to fail, so we do this first. It seems that when an access token is a bit old and is still good
            // for downloading some of the data, it's not good enough to get the salts. We need a fresh one.
            var r = await rest.ExecuteGetAsync<Model.SaltsResponse>(new RestRequest("core/v4/keys/salts"), cancellationToken).ConfigureAwait(false);
            if (!r.IsSuccessful)
                throw MakeError(r);

            var salts = r.Data!.KeySalts;

            // 2. Get the user info that contains the user keys
            var r0 = await rest.ExecuteGetAsync<Model.UserResponse>(new RestRequest("core/v4/users"), cancellationToken).ConfigureAwait(false);
            if (!r0.IsSuccessful)
                throw MakeError(r0);

            var user = r0.Data!.User;
            if (user.Keys.Length == 0)
                throw new InternalErrorException("Expected at least one user key");

            var primaryKey = user.Keys.FirstOrDefault(x => x.Primary == 1);
            if (primaryKey == null)
                throw new InternalErrorException("Expected a primary key");

            // The salt seems to be optional in case of the older accounts. Not sure how to test this IRL.
            // When there's no salt, the master password is the key password.
            var keyPassphrase = DeriveKeyPassphrase(password, salts.FirstOrDefault(x => x.Id == primaryKey.Id)?.Salt);

            // 2. Get all the shares
            var r1 = await rest.ExecuteGetAsync<Model.ShareRoot>(new RestRequest("pass/v1/share"), cancellationToken).ConfigureAwait(false);
            if (!r1.IsSuccessful)
                throw MakeError(r1);

            var shares = r1.Data!.Shares;
            if (shares.Length == 0)
                throw new InternalErrorException("Expected at least one share");

            // TODO: Decide what to do with multiple shares
            if (shares.Length > 1)
                throw new UnsupportedFeatureException("Multiple shares are not supported yet");

            var share = shares[0];
            if (share.TargetType != 1)
                throw new UnsupportedFeatureException("Only vault shares are supported");

            // 3. Get the keys for the share
            var r2 = await rest.ExecuteGetAsync<Model.ShareKeysRoot>(new RestRequest($"pass/v1/share/{share.Id}/key"), cancellationToken).ConfigureAwait(false);
            var shareKeys = r2.Data!.ShareKeys.Keys;

            if (shareKeys.Length == 0)
                throw new InternalErrorException("Expected at least one share key");

            // 4. Get the latest key
            var latestShareKey = shareKeys.MaxBy(x => x.KeyRotation);
            if (latestShareKey == null)
                throw new InternalErrorException("Expected at least one share key");

            // 5. Make sure the user has a matching key
            if (latestShareKey.UserKeyId != primaryKey.Id)
                throw new InternalErrorException($"Share {share.Id} key {latestShareKey.UserKeyId} that doesn't match the user primary key");

            // 6. Decrypt the share key
            var vaultKey = await DecryptMessage(latestShareKey.Key, primaryKey.PrivateKey, keyPassphrase).ConfigureAwait(false);

            // 7. Get the share content
            var r3 = await rest.ExecuteGetAsync<Model.VaultResponse>(new RestRequest($"pass/v1/share/{share.Id}/item"), cancellationToken).ConfigureAwait(false);
            if (!r3.IsSuccessful)
                throw MakeError(r3);

            var vault = r3.Data!.Items;
            foreach (var item in vault.Items)
            {
                var encryptedKey = item.ItemKey.Decode64();
                var key = OnePassword.AesGcm.Decrypt(key: vaultKey,
                                                         ciphertext: encryptedKey.Sub(12, encryptedKey.Length - 12),
                                                         iv: encryptedKey.Sub(0, 12),
                                                         authData: "itemkey".ToBytes());

                var encryptedContent = item.Content.Decode64();
                var content = OnePassword.AesGcm.Decrypt(key: key,
                                                         ciphertext: encryptedContent.Sub(12, encryptedContent.Length - 12),
                                                         iv: encryptedContent.Sub(0, 12),
                                                         authData: "itemcontent".ToBytes());
                // TODO: Decode protobuf here!!!
            }

            return Array.Empty<string>();
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

        public static PgpPrivateKey LoadPrivateKey(string privateKeyBlock, string passphrase)
        {
            using (Stream privateKeyStream = new MemoryStream(Encoding.UTF8.GetBytes(privateKeyBlock)))
            {
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys())
                    {
                        PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(passphrase.ToCharArray());
                        if (privateKey != null)
                        {
                            return privateKey;
                        }
                    }
                }

                throw new ArgumentException("No private key found in the provided key block.");
            }
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

        internal class TokenExpiredException: BaseException
        {
            public TokenExpiredException(): base("Access token expired", null)
            {
            }
        }

        internal class MissingLockedScopeException: BaseException
        {
            public MissingLockedScopeException(): base("Missing locked scope", null)
            {
            }
        }

        internal class NeedCaptchaException: BaseException
        {
            public string Url { get; }
            public string HumanVerificationToken { get; }

            public NeedCaptchaException(string url, string humanVerificationToken):
                base("CAPTCHA verification required", null)
            {
                Url = url;
                HumanVerificationToken = humanVerificationToken;
            }
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

                if (errorCode == 401 && errorText == "Invalid access token")
                    return new TokenExpiredException();

                if (errorCode == 10013 && errorText == "Invalid refresh token")
                    return new TokenExpiredException();

                if (errorCode == 9101 && error!.Details is { } scopeDetails && scopeDetails.MissingScopes?.Contains("locked") == true)
                    return new MissingLockedScopeException();

                // TODO: Check what kind of other human verification methods are there
                if (errorCode == 9001 && error!.Details is { } captchaDetails && captchaDetails.HumanVerificationMethods?.Contains("captcha") == true)
                    // TODO: Verify that the url and the token are set
                    return new NeedCaptchaException(captchaDetails.Url!, captchaDetails.HumanVerificationToken!);

                return new InternalErrorException(
                    $"Request to '{response.ResponseUri}' failed with HTTP status {response.StatusCode} and error {errorCode}: '{errorText}'");
            }

            if (response.IsJsonError())
                return new InternalErrorException("Failed to parse the response JSON", response.ErrorException);

            return new InternalErrorException($"Request to '{response.ResponseUri}' failed", response.ErrorException);
        }

        //
        // Data
        //

        // Web protocol
        // public const string BaseUrl = "https://account.proton.me/api";
        // public const string AppVersion = "web-account@5.0.99.0";

        // Android protocol
        internal const string BaseUrl = "https://pass-api.proton.me";
        internal const string AppVersion = "android-pass@1.19.0";
    }
}
