// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MockHttp;
using MockHttp.Json;
using MockHttp.Language.Flow.Response;
using MockHttp.Language.Response;
using PasswordManagerAccess.Common;
using RestClient = RestSharp.RestClient;

namespace PasswordManagerAccess.Test
{
    internal static class TestUtil
    {
        public static RestAsync.Config ToConfig(this MockHttpHandler mockHttp)
        {
            return new RestAsync.Config
            {
                ConfigureMessageHandler = _ => mockHttp,
            };
        }

        public static RestClient ToClient(this MockHttpHandler mockHttp, string baseUrl = "http://does.not.matter")
        {
            return RestAsync.Create(baseUrl, mockHttp.ToConfig());
        }

        // A json adapter that doesn't do anything
        private class UnitJsonAdapter : IJsonAdapter
        {
            public string Serialize(object? value) => value as string ?? string.Empty;
        }

        public static IWithContentResult JsonText(this IWithContent builder, string json)
        {
            return builder.JsonBody(json, Encoding.UTF8, new UnitJsonAdapter());
        }

        public static RequestMatching JsonText(this RequestMatching builder, string body)
        {
            return builder.JsonBody(body, new UnitJsonAdapter());
        }

        public static RestClient Serve(string body, HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            var mockHttp = new MockHttpHandler();
            mockHttp
                .When(w => { })
                .Respond(w => w.StatusCode(statusCode).Body(body));
            return mockHttp.ToClient();
        }

        public static CancellationToken MakeToken() => new CancellationTokenSource().Token;

        public static async Task Swallow(Func<Task> asyncFunc)
        {
            try
            {
                await asyncFunc().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Ignored
            }
        }

        public static async Task<T> Swallow<T>(Func<Task<T>> asyncFunc)
        {
            try
            {
                return await asyncFunc().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Ignored
            }

            return default!;
        }
    }
}
