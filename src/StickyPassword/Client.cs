// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
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
using PasswordManagerAccess.Common;
using PasswordManagerAccess.StickyPassword.Ui;

namespace PasswordManagerAccess.StickyPassword
{
    internal static class Client
    {
        // TODO: It's impossible to test this function because of the S3.* static calls.
        public static byte[] OpenVaultDb(string username,
                                         string password,
                                         string deviceId,
                                         string deviceName,
                                         IUi ui,
                                         IRestTransport transport)
        {
            var rest = new RestClient(transport, "https://spcb.stickypassword.com/SPCClient/");

            // Request the token that is encrypted with the master password and get the one-time PIN
            // when a new device is registered for the first time.
            var (encryptedToken, passcode) = GetEncryptedTokenAndPasscode(username, deviceId, ui, rest);

            // Decrypt the token. This token is now used to authenticate with the server.
            var token = Util.DecryptToken(username, password, encryptedToken);

            // The device must be registered first.
            AuthorizeDevice(username, token, deviceId, deviceName, passcode, DateTime.Now, rest);

            // Get the S3 credentials to access the database on AWS.
            var s3Token = GetS3Token(username, token, deviceId, DateTime.Now, rest);

            // Download the database.
            return DownloadLatestDb(s3Token, transport);
        }

        //
        // Internal (accessed by the tests)
        //

        internal static (byte[] EncryptedToken, string Passcode) GetEncryptedTokenAndPasscode(string username,
                                                                                              string deviceId,
                                                                                              IUi ui,
                                                                                              RestClient rest)
        {
            byte[] GetToken(string code) => GetEncryptedToken(username, deviceId, code, DateTime.Now, rest);

            // First request without any passcode. This should succeed for known devices.
            var encryptedToken = GetToken(NoPasscode);
            if (encryptedToken != EmailPasscodeRequired)
                return (encryptedToken, NoPasscode);

            // It's a new device, the email PIN is required
            for (;;)
            {
                var passcode = ui.ProvideEmailPasscode();
                if (passcode == Passcode.Cancel)
                    throw new CanceledMultiFactorException("Second factor step is canceled by the user");

                if (passcode == Passcode.Resend)
                {
                    GetToken(NoPasscode);
                    continue;
                }

                // Now try with the PIN from the email
                encryptedToken = GetToken(passcode.Code);
                if (encryptedToken == EmailPasscodeRequired)
                    throw new InternalErrorException("Unexpected response");

                return (encryptedToken, passcode.Code);
            }
        }

        // This function requests an encrypted token for the specified username. There's no
        // authentication of any kind at this point. The token is encrypted with the user's
        // master password. The user should decrypt it and supply with the subsequent POST
        // requests. If the password is incorrect, the following calls will be rejected with
        // the 401 code and the database with fail to download.
        internal static byte[] GetEncryptedToken(string username,
                                                 string deviceId,
                                                 string passcode,
                                                 DateTime timestamp,
                                                 RestClient rest)
        {
            var parameters = new Dictionary<string, object>(2) {["uaid"] = username};
            if (!passcode.IsNullOrEmpty())
                parameters["pin"] = passcode;

            var response = Post(rest, "GetCrpToken", deviceId, timestamp, parameters);
            switch (response.Status)
            {
            case "0":
                return response.Get("/SpcResponse/GetCrpTokenResponse/CrpToken").Decode64();
            case "1006":
                throw new BadCredentialsException("Invalid username");
            case "4002":
                return EmailPasscodeRequired;
            case "4003":
                throw new BadMultiFactorException("Second factor code is not correct");
            default:
                throw CreateException("retrieve the encrypted token", response);
            }
        }

        // The device id and the device name identify the device in use. It's not 100% clear
        // what the id and the name are for. Why not just one? The id is a random string of bytes.
        // The name is the model of the device on Android. The device must be registered before
        // it could be used to download the database. It doesn't return any information back from
        // the server.
        internal static void AuthorizeDevice(string username,
                                             byte[] token,
                                             string deviceId,
                                             string deviceName,
                                             string passcode,
                                             DateTime timestamp,
                                             RestClient rest)
        {
            var parameters = new Dictionary<string, object>(2) {["hid"] = deviceName};
            if (!passcode.IsNullOrEmpty())
                parameters["pin"] = passcode;

            var response = Post(rest,
                                "DevAuth",
                                deviceId,
                                timestamp,
                                parameters,
                                username,
                                token);

            switch (response.Status)
            {
            case "0": // A new device just got registered
            case "4005": // The device is known and has been registered in the past
                return;
            default:
                throw CreateException("authorize the device", response);
            }
        }

        // This function requests the AWS S3 access token and some additional info that
        // is needed to download the database info and the database itself.
        internal static S3Token GetS3Token(string username,
                                           byte[] token,
                                           string deviceId,
                                           DateTime timestamp,
                                           RestClient rest)
        {
            var response = Post(rest,
                                "GetS3Token",
                                deviceId,
                                timestamp,
                                RestClient.NoParameters,
                                username,
                                token);

            if (response.Status != "0")
                throw CreateException("retrieve the S3 token", response);

            return new S3Token(
                accessKeyId: GetS3TokenItem(response, "AccessKeyId"),
                secretAccessKey: GetS3TokenItem(response, "SecretAccessKey"),
                securityToken: GetS3TokenItem(response, "SessionToken"),
                bucketName: GetS3TokenItem(response, "BucketName"),
                objectPrefix: GetS3TokenItem(response, "ObjectPrefix")
            );
        }

        // This functions finds out what the latest version of the database is and downloads
        // it from S3.
        internal static byte[] DownloadLatestDb(S3Token token, IRestTransport transport)
        {
            return DownloadLatestDb(token, new RestClient(transport));
        }

        internal static byte[] DownloadLatestDb(S3Token token, RestClient rest)
        {
            var version = FindLatestDbVersion(token, rest);
            return DownloadDb(version, token, rest);
        }

        internal static string FindLatestDbVersion(S3Token token, RestClient rest)
        {
            // TODO: Sort out binary/text Get
            var info = GetS3Object("1/spc.info", token, "the database info", rest).ToUtf8();

            var re = new Regex(@"VERSION\s+(\d+)");
            var m = re.Match(info);

            if (!m.Success)
                throw new InternalErrorException("Invalid database info format");

            return m.Groups[1].Value;
        }

        internal static byte[] DownloadDb(string version, S3Token token, RestClient rest)
        {
            var db = GetS3Object($"1/db_{version}.dmp", token, "the database", rest);
            return Inflate(db, "the database");
        }

        internal class XmlResponse
        {
            public static XmlResponse Parse(string text)
            {
                try
                {
                    var doc = XDocument.Parse(text);
                    var man = new XmlNamespaceManager(new NameTable());
                    man.AddNamespace(NamespaceName, "http://www.stickypassword.com/cb/clientapi/schema/v2");

                    return new XmlResponse(doc, man);
                }
                catch (XmlException e)
                {
                    throw new InternalErrorException("Failed to parse XML in response", e);
                }
            }

            public string Status { get; }

            // Get is very simple. Every path component must start with /.
            public string Get(string path)
            {
                var e = _document.XPathSelectElement(path.Replace("/", $"/{NamespaceName}:"), _namespaceManager);
                if (e == null)
                    throw new InternalErrorException($"Failed to find '{path}' in response XML");

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

        internal static XmlResponse Post(RestClient rest,
                                         string endpoint,
                                         string deviceId,
                                         DateTime timestamp,
                                         Dictionary<string, object> parameters,
                                         string username = null,
                                         byte[] token = null)
        {
            var headers = new Dictionary<string, string>
            {
                ["Accept"] = "application/xml",
                ["Date"] = timestamp.ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss 'GMT'", EnUs),
                ["User-Agent"] = GetUserAgent(deviceId),
            };

            if (!username.IsNullOrEmpty())
                headers["Authorization"] = GetAuthorizationHeader(username, token);

            var response = rest.PostForm(endpoint, parameters, headers);
            if (response.IsSuccessful)
                return XmlResponse.Parse(response.Content);

            if (response.IsNetworkError)
                throw new NetworkErrorException("Network error has occurred", response.Error);

            // Special handling for 401. There's no other way to tell if the password is correct.
            // TODO: Write a test for this path. Now it should be easy once we transitioned away
            //       from HttpWebResponse.
            if (response.StatusCode == HttpStatusCode.Unauthorized)
                throw new BadCredentialsException("The password is incorrect");

            throw new InternalErrorException(
                $"HTTP request to '{response.RequestUri}' failed with status {response.StatusCode}");
        }

        //
        // Private
        //

        private static InternalErrorException CreateException(string operation, XmlResponse xml)
        {
            return new InternalErrorException($"Failed to {operation} (error: {xml.Status})");
        }

        private static string GetUserAgent(string deviceId)
        {
            return $"SP/8.0.3436 Prot=2 ID={deviceId} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=";
        }

        private static string GetAuthorizationHeader(string username, byte[] token)
        {
            return "Basic " + $"{username}:{token.ToBase64()}".ToBase64();
        }

        private static string GetS3TokenItem(XmlResponse xml, string name)
        {
            return xml.Get($"/SpcResponse/GetS3TokenResponse/{name}");
        }

        private static byte[] GetS3Object(string filename, S3Token token, string name, RestClient rest)
        {
            return S3.GetObject(token.BucketName, token.ObjectPrefix + filename, token.Credentials, rest);
        }

        private static byte[] Inflate(byte[] bytes, string name)
        {
            using var inputStream = new MemoryStream(bytes, false);
            return Inflate(inputStream, name);
        }

        private static byte[] Inflate(Stream s, string name)
        {
            InternalErrorException MakeError(Exception e)
            {
                return new InternalErrorException($"Failed to decompress {name}", e);
            }

            try
            {
                // Eat first two bytes
                // See: http://stackoverflow.com/a/21544269/362938
                s.ReadByte();
                s.ReadByte();

                using var deflateStream = new DeflateStream(s, CompressionMode.Decompress);
                return deflateStream.ReadAll();
            }
            catch (InvalidDataException e)
            {
                throw MakeError(e);
            }
            catch (IOException e)
            {
                throw MakeError(e);
            }
        }

        //
        // Data
        //

        internal static readonly CultureInfo EnUs = new CultureInfo("en-US");

        internal const string NoPasscode = "";
        internal static readonly byte[] EmailPasscodeRequired = {(byte)'P', (byte)'I', (byte)'N'};
    }
}
