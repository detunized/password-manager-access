// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace TrueKey
{
    public static class Remote
    {
        public class DeviceInfo
        {
            public DeviceInfo(string token, string id)
            {
                Token = token;
                Id = id;
            }

            public readonly string Token;
            public readonly string Id;
        }

        // This is the first step in authentication process for a new device.
        // This requests the client token with is used in OCRA (RFC 6287) exchange
        // later on. There's also a server assigned id for the new device.
        //
        // `deviceName` is the name of the device registered with the True Key service.
        // For example 'Chrome' or 'Nexus 5'.
        public static DeviceInfo RegisetNewDevice(string deviceName)
        {
            return RegisetNewDevice(deviceName, new HttpClient());
        }

        //
        // Internal
        //

        internal static DeviceInfo RegisetNewDevice(string deviceName, IHttpClient client)
        {
            var response = Post(client,
                                "https://truekeyapi.intelsecurity.com/sp/pabe/v2/so",
                                new Dictionary<string, string>
                                {
                                    {"clientUDID", "truekey-sharp"},
                                    {"deviceName", deviceName},
                                    {"devicePlatformID", "7"},
                                    {"deviceType", "5"},
                                    {"oSName", "Unknown"},
                                    {"oathTokenType", "1"},
                                });

            // TODO: Verify results
            return new DeviceInfo(response.StringAtOrNull("clientToken"),
                                  response.StringAtOrNull("tkDeviceId"));
        }

        internal static JObject Post(IHttpClient client, string url, Dictionary<string, string> parameters)
        {
            // TODO: Handle network errors
            var response = client.Post(url, parameters);
            var parsed = JObject.Parse(response);

            var success = parsed.AtOrNull("responseResult/isSuccess");
            if (success == null || (bool?)success != true)
                // TODO: Use custom exception
                throw new InvalidOperationException("Operation failed");

            return parsed;
        }
    }
}
