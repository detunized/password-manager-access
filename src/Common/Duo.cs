// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using HtmlAgilityPack;
using Newtonsoft.Json;

namespace PasswordManagerAccess.Common
{
    // Common parts
    internal static partial class Duo
    {
        public class Result
        {
            public readonly string Passcode;
            public readonly bool RememberMe;

            public Result(string passcode, bool rememberMe)
            {
                Passcode = passcode;
                RememberMe = rememberMe;
            }
        }

        //
        // Internal
        //

        internal static HtmlDocument Parse(string html)
        {
            var doc = new HtmlDocument();
            doc.LoadHtml(html);
            return doc;
        }

        internal static InternalErrorException MakeInvalidResponseError(string message)
        {
            return new InternalErrorException(ErrorPrefix + message);
        }

        internal static BaseException MakeSpecializedError(RestResponse response, string extraInfo = "")
        {
            var text = ErrorPrefix + $"rest call to {response.RequestUri} failed";

            if (response.IsHttpError)
                text += $" (HTTP status: {response.StatusCode})";

            if (!extraInfo.IsNullOrEmpty())
                text += extraInfo;

            return new InternalErrorException(text, response.Error);
        }

        internal static BaseException MakeSpecializedError<T>(RestResponse<string, R.Envelope<T>> response)
        {
            var message = response.Data.Message.IsNullOrEmpty() ? "none" : response.Data.Message;
            return MakeSpecializedError(response, $"Server message: {message}");
        }

        //
        // Response models
        //

        internal static partial class R
        {
            public struct Envelope<T>
            {
                [JsonProperty("stat", Required = Required.Always)]
                public string Status;

                [JsonProperty("message")]
                public string Message;

                [JsonProperty("response")]
                public T Payload;
            }
        }

        //
        // Data
        //

        private const string ErrorPrefix = "Duo: ";
    }
}
