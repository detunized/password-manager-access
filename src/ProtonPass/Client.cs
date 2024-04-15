// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using RestSharp;
using RestSharp.Authenticators.OAuth2;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.ProtonPass
{
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
        public static async Task Open(string username,
                                      string password,
                                      IAsyncUi ui,
                                      RestAsync.Config config,
                                      CancellationToken cancellationToken)
        {
            var rest = RestAsync.Create(BaseUrl, config);
            rest.AddDefaultHeader("X-Pm-Appversion", AppVersion);

            // TODO: Only create a session when we don't have one
            var session = await RequestNewAuthSession(rest, cancellationToken).ConfigureAwait(false);

            rest.AddDefaultHeader("X-Pm-Uid", session.Id);
            rest.UpdateAuthenticator(new OAuth2AuthorizationRequestHeaderAuthenticator(session.AccessToken,
                                         session.TokenType));

            var authInfo = await RequestAuthInfo(username, rest, cancellationToken).ConfigureAwait(false);
            var proof = Srp.GenerateProofs(version: authInfo.Version,
                                           password: password,
                                           username: username,
                                           saltBytes: authInfo.Salt.Decode64(),
                                           serverEphemeralBytes: authInfo.ServerEphemeral.Decode64(),
                                           modulusBytes: Srp.ParseModulus(authInfo.Modulus));

            // TODO: Make 3 a const or a config param
            for (var i = 0; i < 3; i++)
            {
                try
                {
                    var v4 = await SubmitSrpProof(username, authInfo.SrpSession, proof, rest, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (NeedCaptchaException e)
                {
                    var result = await ui.SolveCaptcha(e.Url, e.HumanVerificationToken, cancellationToken)
                        .ConfigureAwait(false);
                    if (!result.Solved)
                        throw new InternalErrorException("CAPTCHA verification failed or was cancelled by the user");

                    rest.AddDefaultHeader("X-Pm-Human-Verification-Token-Type", "captcha");
                    rest.AddDefaultHeader("X-Pm-Human-Verification-Token", result.Token);
                }
            }
        }

        //
        // Internal
        //

        internal static async Task<Model.Session> RequestNewAuthSession(RestClient rest,
                                                                        CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4/sessions");
            var response = await rest.ExecutePostAsync<Model.Session>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static async Task<Model.AuthInfo> RequestAuthInfo(string username,
                                                                   RestClient rest,
                                                                   CancellationToken cancellationToken)
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

        private static async Task<object> SubmitSrpProof(string username,
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

            var response = await rest.ExecutePostAsync<Model.AuthInfo>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
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
                    errorText = $" and error {errorCode}: '{error.Text ?? ""}'";
                }

                // TODO: Check what kind of other human verification methods are there
                if (errorCode == 9001 && error!.Details is { } errorDetails &&
                    errorDetails.HumanVerificationMethods?.Contains("captcha") == true)
                {
                    // TODO: Verify that the url and the token are set
                    return new NeedCaptchaException(errorDetails.Url!, errorDetails.HumanVerificationToken!);
                }

                return new InternalErrorException(
                    $"Request to {response.ResponseUri} failed with HTTP status {response.StatusCode}{errorText}");
            }

            if (response.IsJsonError())
                return new InternalErrorException("Failed to parse the response JSON", response.ErrorException);

            return new InternalErrorException($"Request to {response.ResponseUri} failed", response.ErrorException);
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
