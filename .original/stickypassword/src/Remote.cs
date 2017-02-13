// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace StickyPassword
{
    public static class Remote
    {
        public static byte[] GetEncryptedToken(string username, string deviceId, DateTime timestamp)
        {
            return GetEncryptedToken(username, deviceId, timestamp, new HttpClient());
        }

        public static byte[] GetEncryptedToken(string username,
                                               string deviceId,
                                               DateTime timestamp,
                                               IHttpClient client)
        {
            var response = Post(client,
                                "GetCrpToken",
                                deviceId,
                                timestamp,
                                new Dictionary<string, string>
                                {
                                    {"uaid", username},
                                });

            switch (response.Status)
            {
            case "0":
                return response.Get("/SpcResponse/GetCrpTokenResponse/CrpToken").Decode64();
            case "1006":
                throw new FetchException(FetchException.FailureReason.IncorrectUsername,
                                         "Incorrect username");
            default:
                throw CreateException("retrieve the encrypted token", response);
            }
        }

        public static void AuthorizeDevice(string username,
                                           byte[] token,
                                           string deviceId,
                                           string deviceName,
                                           DateTime timestamp)
        {
            AuthorizeDevice(username, token, deviceId, deviceName, timestamp, new HttpClient());
        }

        public static void AuthorizeDevice(string username,
                                           byte[] token,
                                           string deviceId,
                                           string deviceName,
                                           DateTime timestamp,
                                           IHttpClient client)
        {
            var response = Post(client,
                                "DevAuth",
                                deviceId,
                                username,
                                token,
                                timestamp,
                                new Dictionary<string, string>
                                {
                                    {"hid", deviceName}
                                });


            switch (response.Status)
            {
            case "0": // A new device just got registered
                return;
            case "4005": // The device is known and has been registered in the past
                return;
            default:
                throw CreateException("authorize the device", response);
            }
        }

        public static S3Token GetS3Token(string username,
                                         byte[] token,
                                         string deviceId,
                                         DateTime timestamp)
        {
            return GetS3Token(username, token, deviceId, timestamp, new HttpClient());
        }

        public static S3Token GetS3Token(string username,
                                         byte[] token,
                                         string deviceId,
                                         DateTime timestamp,
                                         IHttpClient client)
        {
            var response = Post(client,
                                "GetS3Token",
                                deviceId,
                                username,
                                token,
                                timestamp,
                                new Dictionary<string, string>());

            if (response.Status != "0")
                throw CreateException("retrieve the S3 token", response);

            return new S3Token(
                    accessKeyId: GetS3TokenItem(response, "AccessKeyId"),
                secretAccessKey: GetS3TokenItem(response, "SecretAccessKey"),
                   sessionToken: GetS3TokenItem(response, "SessionToken"),
                 expirationDate: GetS3TokenItem(response, "DateExpiration"),
                     bucketName: GetS3TokenItem(response, "BucketName"),
                   objectPrefix: GetS3TokenItem(response, "ObjectPrefix")
            );
        }

        public static byte[] DownloadLatestDb(S3Token s3Token)
        {
            using (var s3 = new AmazonS3Client(s3Token.AccessKeyId,
                                               s3Token.SecretAccessKey,
                                               s3Token.SessionToken,
                                               RegionEndpoint.USEast1))
                return DownloadLatestDb(s3Token.BucketName, s3Token.ObjectPrefix, s3);
        }

        public static byte[] DownloadLatestDb(string bucketName, string objectPrefix, IAmazonS3 s3)
        {
            var version = FindLatestDbVersion(bucketName, objectPrefix, s3);
            return DownloadDb(version, bucketName, objectPrefix, s3);
        }

        public static string FindLatestDbVersion(string bucketName,
                                                 string objectPrefix,
                                                 IAmazonS3 s3)
        {
            var filename = objectPrefix + "1/spc.info";
            string info;
            using (var response = GetS3Object(s3, bucketName, filename, "the database info"))
                info = response.ResponseStream.ReadAll().ToUtf8();

            var re = new Regex(@"VERSION\s+(\d+)");
            var m = re.Match(info);

            if (!m.Success)
                throw new FetchException(FetchException.FailureReason.InvalidResponse,
                                         "Invalid database info format");

            return m.Groups[1].Value;
        }

        public static byte[] DownloadDb(string version,
                                        string bucketName,
                                        string objectPrefix,
                                        IAmazonS3 s3)
        {
            var filename = string.Format(CultureInfo.InvariantCulture,
                                         "{0}1/db_{1}.dmp",
                                         objectPrefix,
                                         version);
            using (var response = GetS3Object(s3, bucketName, filename, "the database"))
                return Inflate(response.ResponseStream, "the database");
        }

        //
        // Private
        //

        private class XmlResponse
        {
            public static XmlResponse Parse(string text)
            {
                XDocument doc;
                try
                {
                    doc = XDocument.Parse(text);
                }
                catch (XmlException e)
                {
                    throw new FetchException(FetchException.FailureReason.InvalidResponse,
                                             "Unknown response format",
                                             e);
                }

                var man = new XmlNamespaceManager(new NameTable());
                man.AddNamespace(NamespaceName,
                                 "http://www.stickypassword.com/cb/clientapi/schema/v2");

                return new XmlResponse(doc, man);
            }

            public string Status { get; private set; }

            // Get is very simple. Every path component must start with /.
            public string Get(string path)
            {
                var e = _document.XPathSelectElement(path.Replace("/", "/" + NamespaceName + ":"),
                                                     _namespaceManager);
                if (e == null)
                    throw new FetchException(FetchException.FailureReason.InvalidResponse,
                                             "Unknown response format");

                return e.Value;
            }

            private XmlResponse(XDocument document, XmlNamespaceManager namespaceManager)
            {
                _document = document;
                _namespaceManager = namespaceManager;
                Status = Get("/SpcResponse/Status");
            }

            private const string NamespaceName = "ns";

            private readonly XDocument _document;
            private readonly XmlNamespaceManager _namespaceManager;
        }

        private static FetchException CreateException(string operation, XmlResponse xml)
        {
            return new FetchException(FetchException.FailureReason.RespondedWithError,
                                      string.Format(CultureInfo.InvariantCulture,
                                                    "Failed to {0} (error: {1})",
                                                    operation,
                                                    xml.Status));
        }

        private static XmlResponse Post(IHttpClient client,
                                        string endpoint,
                                        string deviceId,
                                        DateTime timestamp,
                                        Dictionary<string, string> parameters)
        {
            return HandlePostResponse(() => client.Post(endpoint,
                                                        GetUserAgent(deviceId),
                                                        timestamp,
                                                        parameters));
        }

        private static XmlResponse Post(IHttpClient client,
                                        string endpoint,
                                        string deviceId,
                                        string username,
                                        byte[] token,
                                        DateTime timestamp,
                                        Dictionary<string, string> parameters)
        {
            return HandlePostResponse(() => client.Post(endpoint,
                                                        GetUserAgent(deviceId),
                                                        GetAuthorizationHeader(username, token),
                                                        timestamp,
                                                        parameters));
        }

        private static XmlResponse HandlePostResponse(Func<string> post)
        {
            try
            {
                return XmlResponse.Parse(post());
            }
            catch (WebException e)
            {
                // Special handling for 401. There's no other way to tell if the password is correct.
                // TODO: Write a test for this path. It's not trivial to mock HttpWebResponse
                //       if at all possible.
                var r = e.Response as HttpWebResponse;
                if (r != null && r.StatusCode == HttpStatusCode.Unauthorized)
                    throw new FetchException(FetchException.FailureReason.IncorrectPassword,
                                             "Incorrect password",
                                             e);

                throw new FetchException(FetchException.FailureReason.NetworkError,
                                         "Network request failed",
                                         e);
            }
        }

        private static string GetUserAgent(string deviceId)
        {
            return string.Format(
                CultureInfo.InvariantCulture,
                "SP/8.0.3436 Prot=2 ID={0} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=",
                deviceId);
        }

        private static string GetAuthorizationHeader(string username, byte[] token)
        {
            return "Basic " +
                   string.Format(CultureInfo.InvariantCulture, "{0}:{1}", username, token.Encode64())
                       .ToBytes()
                       .Encode64();
        }

        private static string GetS3TokenItem(XmlResponse xml, string name)
        {
            return xml.Get("/SpcResponse/GetS3TokenResponse/" + name);
        }

        private static GetObjectResponse GetS3Object(IAmazonS3 s3,
                                                     string bucketName,
                                                     string filename,
                                                     string name)
        {
            try
            {
                return s3.GetObject(bucketName, filename);
            }
            catch (WebException e)
            {
                throw new FetchException(FetchException.FailureReason.NetworkError,
                                         "Failed to download " + name,
                                         e);
            }
            catch (AmazonServiceException e)
            {
                throw new FetchException(FetchException.FailureReason.S3Error,
                                         "Failed to download " + name,
                                         e);
            }
        }

        private static byte[] Inflate(Stream s, string name)
        {
            // Eat first two bytes
            // See: http://stackoverflow.com/a/21544269/362938
            s.ReadByte();
            s.ReadByte();

            try
            {
                return new DeflateStream(s, CompressionMode.Decompress).ReadAll();
            }
            catch (InvalidDataException e)
            {
                throw new FetchException(FetchException.FailureReason.InvalidResponse,
                                         "Failed to decompress " + name,
                                         e);
            }
        }
    }
}
