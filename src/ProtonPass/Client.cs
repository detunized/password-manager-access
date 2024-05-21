// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
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

            if (!humanVerificationTokenType.IsNullOrEmpty() && !humanVerificationToken.IsNullOrEmpty())
            {
                rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token-Type", humanVerificationTokenType!);
                rest.AddOrUpdateDefaultHeader("X-Pm-Human-Verification-Token", humanVerificationToken!);
            }

            // Normally we have 2 login attempts. One to try the access token from the previous session and one to
            // get refresh and get a new token and try with it.
            var maxAttempts = 2;

            // Either it's the first time we're running or the storage is corrupted. We need to start from scratch.
            if (sessionId.IsNullOrEmpty() || accessToken.IsNullOrEmpty() || refreshToken.IsNullOrEmpty())
            {
               await LoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);

               // We just got a fresh set of access tokens. There's no need to refresh anything right now. We remove
               // one attempt.
               maxAttempts--;
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
                    await DownloadVault(rest, cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (TokenExpiredException)
                {
                    if (refreshToken.IsNullOrEmpty() ||
                        !await TryRefreshAuthSessionAndUpdate(sessionId!, refreshToken!, storage, rest, cancellationToken).ConfigureAwait(false))
                    {
                        // The refresh token is expired. We need to do a full login.
                        await LoginAndUpdate(username, password, ui, storage, rest, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
        }

        //
        // Internal
        //

        // This function is full of side effects. It modifies the rest client, the storage and the UI.
        internal static async Task LoginAndUpdate(string username,
                                                  string password,
                                                  IAsyncUi ui,
                                                  IAsyncSecureStorage storage,
                                                  RestClient rest,
                                                  CancellationToken cancellationToken)
        {
            // 1. To start the login sequence we need the session ID and the access token.
            var session = await RequestNewAuthSession(rest, cancellationToken).ConfigureAwait(false);

            // We save the session ID only. The access and the refresh tokens are only good for requesting
            // the auth info at this point. They don't give any other access. We save them after
            // the authorization is granted. The rest we erase.
            await StoreSession(session.Id, null, null, storage).ConfigureAwait(false);

            rest.AddOrUpdateDefaultHeader("X-Pm-Uid", session.Id);
            rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(session.AccessToken, "Bearer"));

            // 2. Request the auth info that contains the SRP challenge and related data.
            var authInfo = await RequestAuthInfo(username, rest, cancellationToken).ConfigureAwait(false);

            // 3. Generate the SRP challenge response.
            var proof = Srp.GenerateProofs(version: authInfo!.Version,
                                           password: password,
                                           username: username,
                                           saltBytes: authInfo.Salt.Decode64(),
                                           serverEphemeralBytes: authInfo.ServerEphemeral.Decode64(),
                                           modulusBytes: Srp.ParseModulus(authInfo.Modulus));

            // TODO: How many attempts do we need here? Do we need more than 1?
            for (var i = 0; i < 3; i++)
            {
                try
                {
                    // 4. Submit the SRP proof to the server. At this point we could get the CAPTCHA challenge.
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

        internal static async Task<string[]> DownloadVault(RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.ExecuteGetAsync<object>(new RestRequest("pass/v1/invite"), cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return Array.Empty<string>();
        }

        internal class TokenExpiredException: BaseException
        {
            public TokenExpiredException(): base("Access token expired", null)
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

                // TODO: Check what kind of other human verification methods are there
                if (errorCode == 9001 && error!.Details is { } errorDetails && errorDetails.HumanVerificationMethods?.Contains("captcha") == true)
                {
                    // TODO: Verify that the url and the token are set
                    return new NeedCaptchaException(errorDetails.Url!, errorDetails.HumanVerificationToken!);
                }

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
