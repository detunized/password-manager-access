// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Globalization;
using System.Threading;
using System.Net;
using System.Net.Http;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class ClientTest
    {
        [Fact]
        public void GetEncryptedToken_returns_response()
        {
            var flow = new RestFlow().Post(GetTokenResponse);
            var token = Client.GetEncryptedToken(Username, DeviceId, Timestamp, flow);

            Assert.Equal(EncryptedToken, token);
        }

        [Fact]
        public void GetEncryptedToken_makes_POST_request_with_specific_url_and_parameters()
        {
            var flow = new RestFlow()
                .Post(GetTokenResponse)
                    .ExpectUrl("https://spcb.stickypassword.com/SPCClient/GetCrpToken")
                    .ExpectContent($"uaid={UrlEncodedUsername}");

            Client.GetEncryptedToken(Username, DeviceId, Timestamp, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void GetEncryptedToken_throws_on_non_zero_status()
        {
            var flow = new RestFlow().Post(ResponseWithError);

            Exceptions.AssertThrowsInternalError(() => Client.GetEncryptedToken(Username, DeviceId, Timestamp, flow),
                                                 "Failed to retrieve the encrypted token");
        }

        [Fact]
        public void GetEncryptedToken_throws_incorrect_username_on_1006_status()
        {
            var flow = new RestFlow().Post(ResponseWithError1006);

            Exceptions.AssertThrowsBadCredentials(() => Client.GetEncryptedToken(Username, DeviceId, Timestamp, flow),
                                                  "Invalid username");
        }

        [Fact]
        public void AuthorizeDevice_makes_POST_request_with_specific_url_and_parameters()
        {
            var flow = new RestFlow()
                .Post(AuthorizeDeviceResponse)
                    .ExpectUrl("https://spcb.stickypassword.com/SPCClient/DevAuth")
                    .ExpectContent($"hid={DeviceName}");

            Client.AuthorizeDevice(Username, Token, DeviceId, DeviceName, Timestamp, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void AuthorizeDevice_throws_on_non_zero_status()
        {
            var flow = new RestFlow().Post(ResponseWithError);

            Exceptions.AssertThrowsInternalError(
                () => Client.AuthorizeDevice(Username, Token, DeviceId, DeviceName, Timestamp, flow),
                "Failed to authorize the device");
        }

        [Fact]
        public void GetS3Token_makes_POST_request_to_specific_url()
        {
            var flow = new RestFlow()
                .Post(GetS3TokenResponse)
                .ExpectUrl("https://spcb.stickypassword.com/SPCClient/GetS3Token");

            Client.GetS3Token(Username, Token, DeviceId, Timestamp, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void GetS3Token_returns_s3_token()
        {
            var flow = new RestFlow().Post(GetS3TokenResponse);
            var s3 = Client.GetS3Token(Username, Token, DeviceId, Timestamp, flow);

            Assert.Equal("ASIAIFIAL3EJEOPJXVCQ", s3.Credentials.AccessKeyId);
            Assert.Equal("TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d", s3.Credentials.SecretAccessKey);
            Assert.Equal("FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1" +
                         "/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp" +
                         "1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dh" +
                         "vf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4" +
                         "cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri" +
                         "8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF",
                         s3.Credentials.SecurityToken);
            Assert.Equal("spclouddata", s3.BucketName);
            Assert.Equal("31645cc8-6ae9-4a22-aaea-557efe9e43af/", s3.ObjectPrefix);
        }

        [Fact]
        public void GetS3Token_throws_on_non_zero_status()
        {
            var flow = new RestFlow().Post(ResponseWithError);

            Exceptions.AssertThrowsInternalError(() => Client.GetS3Token(Username, Token, DeviceId, Timestamp, flow),
                                                 "Failed to retrieve the S3 token");
        }

        [Fact]
        public void FindLatestDbVersion_returns_version_from_s3()
        {
            var flow = new RestFlow().Get(VersionInfo);
            var version = Client.FindLatestDbVersion(new S3Token("", "", "", "", ""), flow);

            Assert.Equal(Version, version);
        }

        [Fact]
        public void FindLatestDbVersion_requests_file_from_s3()
        {
            var flow = new RestFlow()
                .Get(VersionInfo)
                    .ExpectUrl(Bucket)
                    .ExpectUrl(ObjectPrefix)
                    .ExpectUrl("spc.info");

            Client.FindLatestDbVersion(new S3Token("", "", "", Bucket, ObjectPrefix), flow);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("\t\n")]
        [InlineData("VERSION\nMILESTONE\n")]
        public void FindLatestDbVersion_throws_on_invalid_format(string response)
        {
            var flow = new RestFlow().Get(response);

            Exceptions.AssertThrowsInternalError(
                () => Client.FindLatestDbVersion(new S3Token("", "", "", "", ""), flow),
                "Invalid database info format");
        }

        //
        // Post
        //
        // All the network calls go through Client.Post, so it makes sense to test only it for
        // all the common behaviors.
        //

        [Fact]
        public void Post_converts_date_to_utc_and_formats_correctly()
        {
            var timestamp = DateTime.Parse("Tue, 17 Mar 2020 12:34:56 +01:00"); // Local time here
            var flow = new RestFlow()
                .Post(SuccessfulResponse)
                    .ExpectHeader("Date", "Tue, 17 Mar 2020 11:34:56 GMT"); // UTC/GMT time here

            Client.Post(flow, "endpoint", DeviceId, timestamp, RestClient.NoParameters);
        }

        [Fact]
        public void Post_sets_common_headers()
        {
            var flow = new RestFlow()
                .Post(SuccessfulResponse)
                .ExpectHeader("Accept", "application/xml")
                .ExpectHeader("Authorization",
                              "Basic TGFzdFBhc3MuUnVieUBnbWFpTC5jT206WlRRMU1HVmpNMlJsWlRRMk5HTTNaV0V4TlRoallqY3dOMlk0Tm1NMU1tUT0=")
                .ExpectHeader("Date", "Thu, 05 Mar 1998 23:00:00 GMT")
                .ExpectHeader("User-Agent",
                              $"SP/8.0.3436 Prot=2 ID={DeviceId} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=");

            Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters, Username, Token);
        }

        [Theory]
        [InlineData("")]
        [InlineData(">invalid<")]
        [InlineData("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")]
        public void Post_throws_on_invalid_xml(string response)
        {
            var flow = new RestFlow().Post(response);

            Exceptions.AssertThrowsInternalError(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "Failed to parse XML in response");
        }

        [Fact]
        public void Post_throws_on_network_error()
        {
            var flow = new RestFlow().Post(new HttpRequestException());

            Exceptions.AssertThrowsNetworkError(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "Network error has occurred");
        }

        [Fact]
        public void Post_throws_bad_password_on_unauthorized()
        {
            var flow = new RestFlow().Post("", HttpStatusCode.Unauthorized);

            Exceptions.AssertThrowsBadCredentials(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "The password is incorrect");
        }

        [Fact]
        public void Post_throws_on_non_2xx_http_status()
        {
            var flow = new RestFlow().Post("", HttpStatusCode.NotFound);

            Exceptions.AssertThrowsInternalError(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "failed with status");
        }

        //
        // Data
        //

        private const string BaseUrl = "https://spcb.stickypassword.com/SPCClient/";
        internal const string Username = "LastPass.Ruby@gmaiL.cOm";
        private const string UrlEncodedUsername = "LastPass.Ruby%40gmaiL.cOm";
        internal const string DeviceId = "12345678-1234-1234-1234-123456789abc";
        private const string DeviceName = "stickypassword-sharp";

        private static readonly DateTime Timestamp = new DateTime(1998, 3, 6);

        private const string Bucket = "bucket";
        private const string ObjectPrefix = "objectPrefix/";
        private const string Version = "123456789";
        private const string VersionInfo = "VERSION 123456789\nMILESTONE 987654321";

        private const string DbContent = "All your base are belong to us";
        private static readonly byte[] CompressedDbContent =
        {
            0x78, 0x9c, 0x73, 0xcc, 0xc9, 0x51, 0xa8, 0xcc,
            0x2f, 0x2d, 0x52, 0x48, 0x4a, 0x2c, 0x4e, 0x55,
            0x48, 0x2c, 0x4a, 0x55, 0x48, 0x4a, 0xcd, 0xc9,
            0xcf, 0x4b, 0x57, 0x28, 0xc9, 0x57, 0x28, 0x2d,
            0x06, 0x00, 0xa5, 0x50, 0x0a, 0xbe,
        };

        private static readonly byte[] Token = "e450ec3dee464c7ea158cb707f86c52d".ToBytes();
        private static readonly byte[] EncryptedToken =
        {
            0xd8, 0xcc, 0xc2, 0x1c, 0x69, 0x0a, 0xdb, 0xad,
            0x20, 0x95, 0x5c, 0x1b, 0xf0, 0xaf, 0xdf, 0x78,
            0xbb, 0xd0, 0xd0, 0x15, 0xae, 0xe5, 0x27, 0xb7,
            0xff, 0x79, 0xc1, 0x0b, 0xa9, 0x19, 0xce, 0x40,
        };

        internal const string GetTokenResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
                "<GetCrpTokenResponse>" +
                    "<CrpToken>2MzCHGkK260glVwb8K/feLvQ0BWu5Se3/3nBC6kZzkA=</CrpToken>" +
                "</GetCrpTokenResponse>" +
            "</SpcResponse>";

        private const string AuthorizeDeviceResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
                "<AccountInfo>" +
                    "<Expiration>2016-12-16Z</Expiration>" +
                    "<LicType>trial</LicType>" +
                    "<AltEmail></AltEmail>" +
                    "<TFAStatus>off</TFAStatus>" +
                "</AccountInfo>" +
            "</SpcResponse>";

        private const string GetS3TokenResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
                "<AccountInfo>" +
                    "<Expiration>2037-01-01Z</Expiration>" +
                    "<LicType>free</LicType>" +
                    "<AltEmail></AltEmail>" +
                    "<TFAStatus>off</TFAStatus>" +
                "</AccountInfo>" +
                "<GetS3TokenResponse>" +
                    "<AccessKeyId>ASIAIFIAL3EJEOPJXVCQ</AccessKeyId>" +
                    "<SecretAccessKey>TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d</SecretAccessKey>" +
                    "<SessionToken>" +
                        "FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1/" +
                        "7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp1/" +
                        "F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dhvf1" +
                        "YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4cRah" +
                        "eWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri8fe9a" +
                        "5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF" +
                    "</SessionToken>" +
                    "<DateExpiration>2017-01-11T12:24:24.000Z</DateExpiration>" +
                    "<BucketName>spclouddata</BucketName>" +
                    "<ObjectPrefix>31645cc8-6ae9-4a22-aaea-557efe9e43af/</ObjectPrefix>" +
                "</GetS3TokenResponse>" +
            "</SpcResponse>";

        private const string SuccessfulResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
            "</SpcResponse>";

        private const string ResponseWithError =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>13</Status>" +
            "</SpcResponse>";

        private const string ResponseWithError1006 =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>1006</Status>" +
            "</SpcResponse>";

#if FIX_THIS
        [Fact]
        public void DownloadDb_returns_content_from_s3()
        {
            var s3 = SetupS3(CompressedDbContent);

            Assert.Equal(DbContent.ToBytes(), Client.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));
        }

        [Fact]
        public void DownloadDb_requests_file_from_s3()
        {
            var s3 = SetupS3(CompressedDbContent);
            Client.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object);

            s3.Verify(x => x.GetObjectAsync(
                It.Is<string>(s => s == Bucket),
                It.Is<string>(s => s.Contains(ObjectPrefix) && s.Contains(Version)),
                It.IsAny<CancellationToken>()));
        }

        [Fact]
        public void DownloadDb_throws_on_network_error()
        {
            var s3 = SetupS3Error<WebException>();

            var e = Assert.Throws<FetchException>(
                () => Client.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));

            Assert.Equal(FetchException.FailureReason.NetworkError, e.Reason);
            Assert.IsType<WebException>(e.InnerException);
        }

        [Fact]
        public void DownloadDb_throws_on_aws_error()
        {
            var s3 = SetupS3Error<AmazonServiceException>();

            var e = Assert.Throws<FetchException>(
                () => Client.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));

            Assert.Equal(FetchException.FailureReason.S3Error, e.Reason);
            Assert.IsType<AmazonServiceException>(e.InnerException);
        }

        [Fact]
        public void DownloadDb_throws_on_invalid_deflated_content()
        {
            var s3 = SetupS3("Not really deflated");

            var e = Assert.Throws<FetchException>(
                () => Client.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));
            Assert.Equal(FetchException.FailureReason.InvalidResponse, e.Reason);
            Assert.IsType<InvalidDataException>(e.InnerException);
        }

        //
        // Helpers
        //

        private static Mock<IHttpClient> SetupClientForPost(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock
                .Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<DateTime>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private static Mock<IHttpClient> SetupClientForPostError()
        {
            var mock = new Mock<IHttpClient>();
            mock
                .Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<DateTime>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Throws<WebException>();
            return mock;
        }

        private static Mock<IHttpClient> SetupClientForPostWithAuth(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock
                .Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<DateTime>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private static Mock<IHttpClient> SetupClientForPostWithAuthError()
        {
            var mock = new Mock<IHttpClient>();
            mock
                .Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<string>(),
                                   It.IsAny<DateTime>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Throws<WebException>();
            return mock;
        }

        private static Mock<IAmazonS3> SetupS3(string response)
        {
            return SetupS3(response.ToBytes());
        }

        private static Mock<IAmazonS3> SetupS3(byte[] response)
        {
            var s3 = new Mock<IAmazonS3>();
            s3
                .Setup(x => x.GetObjectAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(new Amazon.S3.Model.GetObjectResponse
                {
                    ResponseStream = new MemoryStream(response)
                }));

            return s3;
        }

        private static Mock<IAmazonS3> SetupS3Error<T>() where T : Exception, new()
        {
            var s3 = new Mock<IAmazonS3>();
            s3
                .Setup(x => x.GetObjectAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Throws<T>();

            return s3;
        }

        private void TestThrowsNetworkError(Action<IHttpClient> what,
                                            Func<Mock<IHttpClient>> setup)
        {
            var client = setup();
            var e = Assert.Throws<FetchException>(() => what(client.Object));
            Assert.Equal(FetchException.FailureReason.NetworkError, e.Reason);
            Assert.IsType<WebException>(e.InnerException);
        }

        private void TestOnIncorrectXml(Action<IHttpClient> what,
                                        Func<string, Mock<IHttpClient>> setup)
        {
            var responses = new[]
            {
                "",
                "<xml />",
                ">invalid<",
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            };

            foreach (var i in responses)
            {
                var e = Assert.Throws<FetchException>(() => what(setup(i).Object));
                Assert.Equal(FetchException.FailureReason.InvalidResponse, e.Reason);
            }
        }
#endif
    }

    // These tests (hopefully) run in an isolated thread. Here we change the thread global state which might
    // affect other tests that are running in parallel. `DisableParallelization = true` should prevent this.
    [CollectionDefinition("IsolatedThreadClientTest", DisableParallelization = true)]
    public class IsolatedThreadClientTest
    {
        [Fact]
        public void GetEncryptedToken_formats_date_in_en_culture()
        {
            var savedCulture = Thread.CurrentThread.CurrentCulture;
            var savedUiCulture = Thread.CurrentThread.CurrentUICulture;

            try
            {
                Thread.CurrentThread.CurrentCulture = new CultureInfo("fr-FR");
                Thread.CurrentThread.CurrentUICulture = new CultureInfo("fr-FR");

                var flow = new RestFlow()
                    .Post(ClientTest.GetTokenResponse)
                    .ExpectHeader("Date", "Tue, 17 Mar 2020 11:34:56 GMT"); // UTC/GMT time here

                Client.GetEncryptedToken(ClientTest.Username,
                                         ClientTest.DeviceId,
                                         DateTime.Parse("Tue, 17 Mar 2020 12:34:56 +01:00"), // Local time here
                                         flow);
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = savedCulture;
                Thread.CurrentThread.CurrentUICulture = savedUiCulture;
            }
        }
    }
}
