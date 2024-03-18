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
                ThrowOnAnyError = true,
                ThrowOnDeserializationError = true,

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

        private static readonly JsonSerializerOptions KeepCaseJsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = null,
        };

        //
        // RestSharp.RestClient extensions
        //

        public static void UpdateAuthenticator(this RestSharp.RestClient rest, IAuthenticator authenticator)
        {
            if (!(rest.Options.Authenticator is DelegatingAuthenticator da))
                throw new InternalErrorException("This instance of RestClient is not created via RestAsync.Create");

            da.DelegateTo = authenticator;
        }
    }

    // TODO: Move out of here
    internal class DelegatingAuthenticator: IAuthenticator
    {
        public IAuthenticator? DelegateTo { get; set; }

        public DelegatingAuthenticator(IAuthenticator? delegateTo = null)
        {
            DelegateTo = delegateTo;
        }

        public ValueTask Authenticate(IRestClient client, RestRequest request) =>
            DelegateTo?.Authenticate(client, request) ?? new ValueTask();
    }
}
