// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using RestSharp;
using RestSharp.Authenticators;
using RestSharp.Serializers;
using RestSharp.Serializers.Json;
#if MITM_PROXY
using System.Net;
#endif

namespace PasswordManagerAccess.Common
{
    // TODO: Rename this to something more meaningful
    internal static class RestAsync
    {
        internal class Config
        {
            public string? UserAgent { get; set; } = null;
            public Func<HttpMessageHandler, HttpMessageHandler>? ConfigureMessageHandler { get; set; }
        }

        public static RestSharp.RestClient Create(string baseUrl, Config config)
        {
            var options = new RestClientOptions(baseUrl)
            {
                UserAgent = config.UserAgent,
                ConfigureMessageHandler = config.ConfigureMessageHandler,
                // TODO: We need these for the tests, but don't need them for prod.
                //ThrowOnAnyError = true,
                //ThrowOnDeserializationError = true,

                // There's no way to set the authenticator later. We use a delegating authenticator that by default
                // does nothing. It could be updated to delegate to a different authenticator later.
                Authenticator = new DelegatingAuthenticator(),

#if MITM_PROXY
                Proxy = new WebProxy("http://127.0.0.1:8888"),
#endif
            };

            return new RestSharp.RestClient(options, configureSerialization: ConfigureSerialization);
        }

        //
        // Private
        //

        private static void ConfigureSerialization(SerializerConfig config)
        {
            config.UseSystemTextJson(KeepCaseJsonOptions);
        }

        private static readonly JsonSerializerOptions KeepCaseJsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };

        //
        // RestSharp.RestClient extensions
        //

        public static RestSharp.RestClient AddOrUpdateDefaultHeader(this RestSharp.RestClient rest, string name, string value)
        {
            rest.DefaultParameters.ReplaceParameter(new HeaderParameter(name, value));
            return rest;
        }

        public static RestSharp.RestClient UpdateAuthenticator(this RestSharp.RestClient rest, IAuthenticator authenticator)
        {
            if (rest.Options.Authenticator is not DelegatingAuthenticator da)
                throw new InternalErrorException("This instance of RestClient is not created via RestAsync.Create");

            da.DelegateTo = authenticator;
            return rest;
        }

        //
        // RestSharp.RestResponse extensions
        //

        // RestSharp marks all the responses with non 200 or 404 status as errors. So we try to heuristically
        // match the actual network errors here. In those cases usually there's no status code and the error contains
        // an inner exception.
        public static bool IsNetworkError(this RestSharp.RestResponse response) =>
            response is { StatusCode: 0, ErrorException: HttpRequestException { InnerException: not null } };

        public static bool IsJsonError(this RestSharp.RestResponse response) => response.ErrorException is JsonException _;

        //
        // JsonSerializer extensions
        //

        public static bool TryDeserialize<T>(string json, out T? result)
            where T : class => TryDeserialize(json, out result, out _);

        public static bool TryDeserialize<T>(string json, out T? result, out JsonException? error)
            where T : class
        {
            try
            {
                result = JsonSerializer.Deserialize<T>(json);
                error = null;
                return result != null;
            }
            catch (JsonException e)
            {
                result = null;
                error = e;
            }

            return false;
        }
    }

    // TODO: Move out of here
    internal class DelegatingAuthenticator : IAuthenticator
    {
        public IAuthenticator? DelegateTo { get; set; }

        public DelegatingAuthenticator(IAuthenticator? delegateTo = null)
        {
            DelegateTo = delegateTo;
        }

        public ValueTask Authenticate(IRestClient client, RestRequest request) => DelegateTo?.Authenticate(client, request) ?? new ValueTask();
    }
}
