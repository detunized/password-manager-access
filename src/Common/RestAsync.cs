// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Net.Http;
using System.Text.Json;
using RestSharp;
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
            public Func<HttpMessageHandler, HttpMessageHandler>? ConfigureMessageHandler { get; set; }
        }

        public static RestSharp.RestClient Create(string baseUrl, Config config)
        {
            var options = new RestClientOptions(baseUrl)
            {
#if MITM_PROXY
                Proxy = new WebProxy("http://127.0.0.1:8888"),
#endif
                ConfigureMessageHandler = config.ConfigureMessageHandler,
                ThrowOnAnyError = true,
                ThrowOnDeserializationError = true,
            };

            var rest = new RestSharp.RestClient(options, configureSerialization: ConfigureSerialization);
            rest.AddDefaultHeader("User-Agent", "");

            return rest;
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

        // ...
    }
}
