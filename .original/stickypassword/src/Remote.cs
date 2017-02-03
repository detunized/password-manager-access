// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using Amazon;
using Amazon.S3;

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

            var xml = XmlResponse.Parse(response);
            if (xml.Status == null || xml.Status != "0")
                throw new InvalidOperationException();

            var token = xml.Get("/SpcResponse/GetCrpTokenResponse/CrpToken");
            if (token == null)
                throw new InvalidOperationException();

            return token.Decode64();
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

            var xml = XmlResponse.Parse(response);
            if (xml.Status == null)
                throw new InvalidOperationException();

            // A new device just got registered
            if (xml.Status == "0")
                return;

            // The device is known and has been registered in the past
            if (xml.Status == "4005")
                return;

            // TODO: Use custom exception
            throw new InvalidOperationException("Device authorization failed");
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

            var xml = XmlResponse.Parse(response);
            if (xml.Status == null || xml.Status != "0")
                throw new InvalidOperationException();

            return new S3Token(
                    accessKeyId: GetS3TokenItem(xml, "AccessKeyId"),
                secretAccessKey: GetS3TokenItem(xml, "SecretAccessKey"),
                   sessionToken: GetS3TokenItem(xml, "SessionToken"),
                 expirationDate: GetS3TokenItem(xml, "DateExpiration"),
                     bucketName: GetS3TokenItem(xml, "BucketName"),
                   objectPrefix: GetS3TokenItem(xml, "ObjectPrefix")
            );
        }

        public static byte[] DownloadLastestDb(S3Token s3Token)
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

        public static string FindLastestDbVersion(string bucketName,
                                                  string objectPrefix,
                                                  IAmazonS3 s3)
        {
            // TODO: Handle S3 errors
            var response = s3.GetObject(bucketName, objectPrefix + "1/spc.info");
            var info = response.ResponseStream.ReadAll().ToUtf8();

            var re = new Regex(@"VERSION\s+(\d+)");
            var m = re.Match(info);

            if (!m.Success)
                throw new InvalidOperationException("Invalid database info format");

            return m.Groups[1].Value;
        }

        public static byte[] DownloadDb(string version,
                                        string bucketName,
                                        string objectPrefix,
                                        IAmazonS3 s3)
        {
            // TODO: Handle S3 errors
            var filename = string.Format("{0}1/db_{1}.dmp", objectPrefix, version);
            var response = s3.GetObject(bucketName, filename);
            return Inflate(response.ResponseStream);
        }

        //
        // Private
        //

        private class XmlResponse
        {
            public static XmlResponse Parse(string text)
            {
                var doc = XDocument.Parse(text);
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
                return e == null ? null : e.Value;
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

        private static string Post(IHttpClient client,
                                   string endpoint,
                                   string deviceId,
                                   DateTime timestamp,
                                   Dictionary<string, string> parameters)
        {
            return client.Post(endpoint, GetUserAgent(deviceId), timestamp, parameters);
        }

        private static string Post(IHttpClient client,
                                   string endpoint,
                                   string deviceId,
                                   string username,
                                   byte[] token,
                                   DateTime timestamp,
                                   Dictionary<string, string> parameters)
        {
            return client.Post(endpoint,
                               GetUserAgent(deviceId),
                               GetAuthorizationHeader(username, token),
                               timestamp,
                               parameters);
        }

        private static string GetUserAgent(string deviceId)
        {
            return string.Format(
                "SP/8.0.3436 Prot=2 ID={0} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=",
                deviceId);
        }

        private static string GetAuthorizationHeader(string username, byte[] token)
        {
            return "Basic " +
                   string.Format("{0}:{1}", username, token.Encode64()).ToBytes().Encode64();
        }

        private static string GetS3TokenItem(XmlResponse xml, string name)
        {
            var item = xml.Get("/SpcResponse/GetS3TokenResponse/" + name);
            if (item == null)
                // TODO: Use custom exception
                throw new InvalidOperationException();

            return item;
        }

        private static byte[] Inflate(Stream s)
        {
            // Eat first two bytes
            // See: http://stackoverflow.com/a/21544269/362938
            s.ReadByte();
            s.ReadByte();

            return new DeflateStream(s, CompressionMode.Decompress).ReadAll();
        }
    }
}
