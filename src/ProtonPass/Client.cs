// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using RestSharp;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.ProtonPass
{
    internal static class Client
    {
        // Web protocol
        // public const string BaseUrl = "https://account.proton.me/api";
        // public const string AppVersion = "web-account@5.0.99.0";

        // Android protocol
        internal const string BaseUrl = "https://pass-api.proton.me";
        internal const string AppVersion = "android-pass@1.19.0";

        public static async Task Open(string username,
                                      string password,
                                      RestAsync.Config config,
                                      CancellationToken cancellationToken)
        {
            var rest = RestAsync.Create(BaseUrl, config);
            rest.AddDefaultHeader("X-Pm-Appversion", AppVersion);

            // TODO: Only create a session when we don't have one
            var session = await CreateSession(rest, cancellationToken);
        }

        //
        // Internal
        //

        internal static async Task<Model.Session> CreateSession(RestClient rest, CancellationToken cancellationToken)
        {
            var request = new RestRequest("auth/v4/sessions");
            var response = await rest.ExecutePostAsync<Model.Session>(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessful)
                throw MakeError(response);

            return response.Data!;
        }

        internal static BaseException MakeError<T>(RestSharp.RestResponse<T> response)
        {
            if (response.IsNetworkError())
                return new NetworkErrorException("Network error", response.ErrorException);

            if (!response.IsSuccessStatusCode)
            {
                // Try to parse the error object from the response
                var errorText = "";
                if (RestAsync.TryDeserialize<Model.Error>(response.Content ?? "", out var error))
                    errorText = $" and error {error!.Code}: '{error.Text ?? ""}'";

                return new InternalErrorException(
                    $"Request to {response.ResponseUri} failed with HTTP status {response.StatusCode}{errorText}");
            }

            if (response.IsJsonError())
                return new InternalErrorException("Failed to parse the response JSON", response.ErrorException);

            return new InternalErrorException($"Request to {response.ResponseUri} failed", response.ErrorException);
        }
    }
}
