// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using HtmlAgilityPack;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo.Response;
using RestSharp;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.Duo
{
    // Only for internal use of Duo.*
    internal static class Util
    {
        public class RestTransportToHttpMessageHandlerAdapter: HttpMessageHandler
        {
            private readonly IRestTransport _transport;

            public RestTransportToHttpMessageHandlerAdapter(IRestTransport transport)
            {
                _transport = transport;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                // The cookies are coming in the headers, so we have to parse them out
                var cookies = new Dictionary<string, string>();
                if (request.Headers.TryGetValues("Cookie", out var cookieHeader))
                {
                    var cc = new CookieContainer();
                    cc.SetCookies(request.RequestUri!, cookieHeader.JoinToString("; "));
                    cookies = cc.GetCookies(request.RequestUri).Cast<Cookie>().ToDictionary(x => x.Name, x => x.Value);
                }

                var result = new Common.RestResponse<string>();
                _transport.MakeRequest(request.RequestUri,
                                       request.Method,
                                       request.Content,
                                       request.Headers.ToDictionary(x => x.Key, x => x.Value.First()),
                                       cookies,
                                       0,
                                       result);

                var response = new HttpResponseMessage(result.StatusCode)
                {
                    Content = new StringContent(result.Content),
                };

                foreach (var header in result.Headers)
                    response.Headers.TryAddWithoutValidation(header.Key, header.Value);

                // Need to convert the cookies into the Set-Cookie headers for RestClient to pick them up
                foreach (var cookie in result.Cookies)
                    response.Headers.TryAddWithoutValidation("Set-Cookie", $"{cookie.Key}={cookie.Value}");

                return Task.FromResult(response);
            }
        }

        internal static HtmlDocument Parse(string html)
        {
            var doc = new HtmlDocument();
            doc.LoadHtml(html);
            return doc;
        }

        internal static async Task<T> PostForm<T>(string endpoint,
                                                  Dictionary<string, object> parameters,
                                                  Dictionary<string, string> headers,
                                                  Dictionary<string, string> cookies,
                                                  RestClient rest,
                                                  CancellationToken cancellationToken)
        {
            var response = await rest.PostForm<Envelope<T>>(endpoint,
                                                            parameters,
                                                            headers: headers,
                                                            cookies: cookies,
                                                            cancellationToken).ConfigureAwait(false);

            // All good
            if (response.IsSuccessful && response.Data.Status == "OK" && response.Data.Payload != null)
                return response.Data.Payload;

            throw MakeSpecializedError(response, rest);
        }

        internal static string GetFactorParameterValue(DuoFactor factor)
        {
            return factor switch
            {
                DuoFactor.Push => "Duo Push",
                DuoFactor.Call => "Phone Call",
                DuoFactor.Passcode => "Passcode",
                DuoFactor.SendPasscodesBySms => "sms",
                _ => ""
            };
        }

        internal static void UpdateUi(DuoStatus status, string text, IDuoUi ui)
        {
            if (text.IsNullOrEmpty())
                return;

            ui.UpdateDuoStatus(status, text);
        }

        internal static InternalErrorException MakeInvalidResponseError(string message)
        {
            return new InternalErrorException(ErrorPrefix + message);
        }

        internal static BaseException MakeSpecializedError(RestSharp.RestResponse response, RestClient rest, string extraInfo = "")
        {
            var uri = rest.BuildUri(response.Request);
            var text = ErrorPrefix + $"rest call to {uri} failed";

            if (!response.IsSuccessStatusCode)
                text += $" (HTTP status: {response.StatusCode})";

            if (!extraInfo.IsNullOrEmpty())
                text += extraInfo;

            return new InternalErrorException(text, response.ErrorException);
        }

        internal static BaseException MakeSpecializedError<T>(RestSharp.RestResponse<Envelope<T>> response, RestClient rest)
        {
            var message = response.Data.Message.IsNullOrEmpty() ? "none" : response.Data.Message;
            return MakeSpecializedError(response, rest, $"Server message: {message}");
        }

        //
        // Data
        //

        private const string ErrorPrefix = "Duo: ";
    }
}
