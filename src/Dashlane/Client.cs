// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    using R = Response;

    // TODO: Merge this with ClientWeb
    internal static class Client
    {
        internal static R.Vault Fetch(string username, string deviceId, IRestTransport transport)
        {
            var rest = new RestClient(transport, BaseApiUrl);

            var parameters = CommonFetchParameters(username);
            parameters["uki"] = deviceId;

            return Fetch(parameters, rest);
        }

        internal static Dictionary<string, object> CommonFetchParameters(string username)
        {
            return new Dictionary<string, object>
            {
                {"login", username},
                {"lock", "nolock"},
                {"timestamp", "0"},
                {"sharingTimestamp", "0"},
            };
        }

        internal static R.Vault Fetch(Dictionary<string, object> parameters, RestClient rest)
        {
            var response = rest.PostForm<R.Vault>(LatestEndpoint, parameters);
            if (response.IsSuccessful)
                return response.Data;

            CheckForErrors(response);

            throw new NetworkErrorException("Network error occurred", response.Error);
        }

        //
        // Private
        //

        private static void CheckForErrors(RestResponse<string> response)
        {
            var json = ParseJson(response);
            var error = json.SelectToken("error");
            if (error != null)
            {
                var message = GetStringProperty(error, "message", "Unknown error");
                throw new InternalErrorException($"Request to '{response.RequestUri}' failed with error: '{message}'");
            }

            if (GetStringProperty(json, "objectType", "") == "message")
            {
                var message = GetStringProperty(json, "content", "Unknown error");
                switch (message)
                {
                case "Incorrect authentification": // Important: it's misspelled in the original code
                    throw new BadMultiFactorException("Invalid UKI or email token");
                case "Bad OTP":
                    throw new BadMultiFactorException("Invalid second factor code");
                default:
                    throw new InternalErrorException(
                        $"Request to '{response.RequestUri}' failed with error: '{message}'");
                }
            }
        }

        private static JObject ParseJson(RestResponse<string> response)
        {
            try
            {
                return JObject.Parse(response.Content);
            }
            catch (JsonException e)
            {
                throw new InternalErrorException($"Invalid JSON in response from '{response.RequestUri}'", e);
            }
        }

        private static string GetStringProperty(JToken root, string name, string defaultValue)
        {
            var token = root.SelectToken(name);
            return token == null || token.Type != JTokenType.String ? defaultValue : (string)token;
        }

        //
        // Data
        //

        private const string BaseApiUrl = "https://ws1.dashlane.com/";
        private const string LatestEndpoint = "12/backup/latest";
    }
}
