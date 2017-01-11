// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Amazon;
using Amazon.S3;
using RestSharp;
using RestSharp.Deserializers;
using RestSharp.Extensions;

namespace StickyPassword
{
    public static class Remote
    {
        private const string ApiUrl = "https://spcb.stickypassword.com/SPCClient/";

        public static byte[] GetEncryptedToken(string username, string deviceId, DateTime timestamp)
        {
            return GetEncryptedToken(username, deviceId, timestamp, new RestClient());
        }

        public class GetCrpTokenResponse
        {
            public string CrpToken { get; set; }
        }

        public class SpcResponse
        {
            public int Status { get; set; }
            public GetCrpTokenResponse GetCrpTokenResponse { get; set; }
        }

        public static byte[] GetEncryptedToken(string username, string deviceId, DateTime timestamp, IRestClient client)
        {
            ConfigureClient(client, deviceId);
            var response = Post(client, "GetCrpToken", timestamp, new Dictionary<string, string>
            {
                {"uaid", username},
            });

            var parsed = new XmlDeserializer().Deserialize<SpcResponse>(response);
            if (parsed == null || parsed.GetCrpTokenResponse == null)
                throw new InvalidOperationException();

            return parsed.GetCrpTokenResponse.CrpToken.Decode64();
        }

        public static void AuthorizeDevice(string username, byte[] token, string deviceId, string deviceName,
            DateTime timestamp)
        {
            AuthorizeDevice(username, token, deviceId, deviceName, timestamp, new RestClient());
        }

        public static void AuthorizeDevice(string username, byte[] token, string deviceId, string deviceName,
            DateTime timestamp, IRestClient client)
        {
            ConfigureClient(client, deviceId);
            var response = Post(client, "DevAuth", timestamp, username, token, new Dictionary<string, string>
            {
                {"hid", deviceName}
            });

            // TODO: Use a different class
            var parsed = new XmlDeserializer().Deserialize<SpcResponse>(response);
            if (parsed == null)
                throw new InvalidOperationException();

            // A new device just got registered
            if (parsed.Status == 0)
                return;

            // The device is known and has been registered in the past
            if (parsed.Status == 4005)
                return;

            // TODO: Use custom exception
            throw new InvalidOperationException("Device authorization failed");
        }

        public class GetS3TokenResponse
        {
            public string AccessKeyId { get; set; }
            public string SecretAccessKey { get; set; }
            public string SessionToken { get; set; }
            public string DateExpiration { get; set; }
            public string BucketName { get; set; }
            public string ObjectPrefix { get; set; }
        }

        public static GetS3TokenResponse GetS3Token(string username, byte[] token, string deviceId, DateTime timestamp)
        {
            return GetS3Token(username, token, deviceId, timestamp, new RestClient());
        }

        public static GetS3TokenResponse GetS3Token(string username, byte[] token, string deviceId, DateTime timestamp, IRestClient client)
        {
            ConfigureClient(client, deviceId);
            var response = Post(client, "GetS3Token", timestamp, username, token, new Dictionary<string, string>());

            // TODO: Use a different class
            var parsed = new XmlDeserializer().Deserialize<SpcResponse>(response);
            if (parsed == null)
                throw new InvalidOperationException();

            if (parsed.Status != 0)
                throw new InvalidOperationException("Failed to retrieve the S3 token");

            var result = new XmlDeserializer().Deserialize<GetS3TokenResponse>(response);
            if (result == null)
                throw new InvalidOperationException();

            return result;
        }

        public static byte[] DownloadLastestDb(GetS3TokenResponse s3Token)
        {
            using (var s3 = new AmazonS3Client(s3Token.AccessKeyId,
                                               s3Token.SecretAccessKey,
                                               s3Token.SessionToken,
                                               RegionEndpoint.USEast1))
                return DownloadLastestDb(s3Token.BucketName, s3Token.ObjectPrefix, s3);
        }

        public static byte[] DownloadLastestDb(string bucketName, string objectPrefix, IAmazonS3 s3)
        {
            var version = FindLastestDbVersion(bucketName, objectPrefix, s3);
            return DownloadDb(version, bucketName, objectPrefix, s3);
        }

        public static string FindLastestDbVersion(string bucketName, string objectPrefix, IAmazonS3 s3)
        {
            // TODO: Handle S3 errors
            var response = s3.GetObject(bucketName, objectPrefix + "1/spc.info");
            var info = response.ResponseStream.ReadAsBytes().ToUtf8();

            var re = new Regex(@"VERSION\s+(\d+)");
            var m = re.Match(info);

            if (!m.Success)
                throw new InvalidOperationException("Invalid database info format");

            return m.Groups[1].Value;
        }

        public static byte[] DownloadDb(string version, string bucketName, string objectPrefix, IAmazonS3 s3)
        {
            // TODO: Handle S3 errors
            var filename = string.Format("{0}1/db_{1}.dmp", objectPrefix, version);
            var response = s3.GetObject(bucketName, filename);
            return response.ResponseStream.ReadAsBytes();
        }

        //
        // Private
        //

        private static void ConfigureClient(IRestClient client, string deviceId)
        {
            client.BaseUrl = new Uri(ApiUrl);
            client.UserAgent = GetUserAgent(deviceId);
        }

        private static string GetUserAgent(string deviceId)
        {
            return string.Format("SP/8.0.3436 Prot=2 ID={0} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=", deviceId);
        }

        private static IRestResponse Post(IRestClient client, string endPoint, DateTime timestamp,
            Dictionary<string, string> parameters)
        {
            return client.Execute(CreatePostRequest(endPoint, timestamp, parameters));
        }

        private static IRestResponse Post(IRestClient client, string endPoint, DateTime timestamp, string username,
            byte[] token, Dictionary<string, string> parameters)
        {
            var request = CreatePostRequest(endPoint, timestamp, parameters);
            SetAuthorizationHeaders(request, username, token);

            return client.Execute(request);
        }

        private static IRestRequest CreatePostRequest(string endPoint, DateTime timestamp,
            Dictionary<string, string> parameters)
        {
            var request = new RestRequest(endPoint, Method.POST);
            SetRequestHeaders(request, timestamp);

            foreach (var i in parameters)
                request.AddParameter(i.Key, i.Value);

            return request;
        }

        private static void SetRequestHeaders(IRestRequest request, DateTime timestamp)
        {
            request.AddHeader("Date", timestamp.ToUniversalTime().ToString("R"));
            request.AddHeader("Accept", "application/xml");
        }

        private static void SetAuthorizationHeaders(IRestRequest request, string username, byte[] token)
        {
            request.AddHeader("Authorization", GetAuthorizationHeader(username, token));
        }

        private static string GetAuthorizationHeader(string username, byte[] token)
        {
            return "Basic " + string.Format("{0}:{1}", username, token.Encode64()).ToBytes().Encode64();
        }
    }
}
