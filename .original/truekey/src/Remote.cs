// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace TrueKey
{
    public interface IHttpClient
    {
        string Post(string url, Dictionary<string, string> parameters);
    }

    public class HttpClient: IHttpClient
    {
        public string Post(string url, Dictionary<string, string> parameters)
        {
            return "";
        }
    }

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
            return new DeviceInfo((string)response.clientToken, (string)response.tkDeviceId);
        }

        internal static dynamic Post(IHttpClient client, string url, Dictionary<string, string> parameters)
        {
            // TODO: Handle network errors
            var response = client.Post(url, parameters);
            return JObject.Parse(response);
        }
    }
}
