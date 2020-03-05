// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Runtime;
using Amazon.S3;
using Moq;
using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class RemoteTest
    {
        private const string Username = "LastPass.Ruby@gmaiL.cOm";
        private const string DeviceId = "12345678-1234-1234-1234-123456789abc";
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
            0x06, 0x00, 0xa5, 0x50, 0x0a, 0xbe
        };

        private static readonly byte[] Token = "e450ec3dee464c7ea158cb707f86c52d".ToBytes();
        private static readonly byte[] EncryptedToken =
        {
            0xd8, 0xcc, 0xc2, 0x1c, 0x69, 0x0a, 0xdb, 0xad,
            0x20, 0x95, 0x5c, 0x1b, 0xf0, 0xaf, 0xdf, 0x78,
            0xbb, 0xd0, 0xd0, 0x15, 0xae, 0xe5, 0x27, 0xb7,
            0xff, 0x79, 0xc1, 0x0b, 0xa9, 0x19, 0xce, 0x40
        };

        private const string GetTokenResponse =
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

        [Fact]
        public void GetEncryptedToken_makes_post_request()
        {
            var client = SetupClientForPost(GetTokenResponse);
            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.Verify(x => x.Post(It.Is<string>(s => s == "GetCrpToken"),
                                      It.Is<string>(s => s.Contains(DeviceId)),
                                      It.Is<DateTime>(d => d == Timestamp),
                                      It.Is<Dictionary<string, string>>(
                                          d => d.ContainsKey("uaid") && d["uaid"] == Username)));
        }

        [Fact]
        public void GetEncryptedToken_returns_response()
        {
            Assert.Equal(EncryptedToken,
                         Remote.GetEncryptedToken(Username,
                                                  DeviceId,
                                                  Timestamp,
                                                  SetupClientForPost(GetTokenResponse).Object));
        }

        [Fact]
        public void GetEncryptedToken_throws_on_network_error()
        {
            TestThrowsNetworkError(client => Remote.GetEncryptedToken(Username,
                                                                      DeviceId,
                                                                      Timestamp,
                                                                      client),
                                   SetupClientForPostError);
        }

        [Fact]
        public void GetEncryptedToken_throws_on_non_zero_status()
        {
            Assert.Throws<FetchException>(
                () => Remote.GetEncryptedToken(Username,
                                               DeviceId,
                                               Timestamp,
                                               SetupClientForPost(ResponseWithError).Object));
        }

        [Fact]
        public void GetEncryptedToken_throws_incorrect_username_on_1006_status()
        {
            var e = Assert.Throws<FetchException>(
                () => Remote.GetEncryptedToken(Username,
                                               DeviceId,
                                               Timestamp,
                                               SetupClientForPost(ResponseWithError1006).Object));
            Assert.Equal(FetchException.FailureReason.IncorrectUsername, e.Reason);
        }

        [Fact]
        public void GetEncryptedToken_throws_on_incorrect_xml()
        {
            TestOnIncorrectXml(client => Remote.GetEncryptedToken(Username,
                                                                  DeviceId,
                                                                  Timestamp,
                                                                  client),
                               SetupClientForPost);
        }

        [Fact]
        public void AuthorizeDevice_makes_post_request()
        {
            var client = SetupClientForPostWithAuth(AuthorizeDeviceResponse);
            Remote.AuthorizeDevice(Username, Token, DeviceId, DeviceName, Timestamp, client.Object);

            client.Verify(x => x.Post(It.Is<string>(s => s == "DevAuth"),
                                      It.Is<string>(s => s.Contains(DeviceId)),
                                      It.Is<string>(s => s.StartsWith("Basic ")),
                                      It.Is<DateTime>(d => d == Timestamp),
                                      It.Is<Dictionary<string, string>>(
                                          d => d.ContainsKey("hid") && d["hid"] == DeviceName)));
        }

        [Fact]
        public void AuthorizeDevice_throws_on_network_error()
        {
            TestThrowsNetworkError(client => Remote.AuthorizeDevice(Username,
                                                                    Token,
                                                                    DeviceId,
                                                                    DeviceName,
                                                                    Timestamp,
                                                                    client),
                                   SetupClientForPostWithAuthError);
        }

        [Fact]
        public void AuthorizeDevice_throws_on_non_zero_status()
        {
            Assert.Throws<FetchException>(
                () => Remote.AuthorizeDevice(Username,
                                             Token,
                                             DeviceId,
                                             DeviceName,
                                             Timestamp,
                                             SetupClientForPostWithAuth(ResponseWithError).Object));
        }

        [Fact]
        public void AuthorizeDevice_throws_on_incorrect_xml()
        {
            TestOnIncorrectXml(client => Remote.AuthorizeDevice(Username,
                                                                Token,
                                                                DeviceId,
                                                                DeviceName,
                                                                Timestamp,
                                                                client),
                               SetupClientForPostWithAuth);
        }

        [Fact]
        public void GetS3Token_makes_post_request()
        {
            var client = SetupClientForPostWithAuth(GetS3TokenResponse);
            Remote.GetS3Token(Username, Token, DeviceId, Timestamp, client.Object);

            client.Verify(x => x.Post(It.Is<string>(s => s == "GetS3Token"),
                                      It.Is<string>(s => s.Contains(DeviceId)),
                                      It.Is<string>(s => s.StartsWith("Basic ")),
                                      It.Is<DateTime>(d => d == Timestamp),
                                      It.Is<Dictionary<string, string>>(d => d.Count == 0)));
        }

        [Fact]
        public void GetS3Token_returns_s3_token()
        {
            var client = SetupClientForPostWithAuth(GetS3TokenResponse);
            var s3 = Remote.GetS3Token(Username, Token, DeviceId, Timestamp, client.Object);

            Assert.Equal("ASIAIFIAL3EJEOPJXVCQ", s3.AccessKeyId);
            Assert.Equal("TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d", s3.SecretAccessKey);
            Assert.Equal("FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1" +
                         "/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp" +
                         "1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dh" +
                         "vf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4" +
                         "cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri" +
                         "8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF",
                         s3.SessionToken);
            Assert.Equal("2017-01-11T12:24:24.000Z", s3.ExpirationDate);
            Assert.Equal("spclouddata", s3.BucketName);
            Assert.Equal("31645cc8-6ae9-4a22-aaea-557efe9e43af/", s3.ObjectPrefix);
        }

        [Fact]
        public void GetS3Token_throws_on_non_zero_status()
        {
            Assert.Throws<FetchException>(
                () => Remote.GetS3Token(Username,
                                        Token,
                                        DeviceId,
                                        Timestamp,
                                        SetupClientForPostWithAuth(ResponseWithError).Object));
        }

        [Fact]
        public void GetS3Token_throws_on_network_error()
        {
            TestThrowsNetworkError(client => Remote.GetS3Token(Username,
                                                               Token,
                                                               DeviceId,
                                                               Timestamp,
                                                               client),
                                   SetupClientForPostWithAuthError);
        }

        [Fact]
        public void GetS3Token_throws_on_incorrect_xml()
        {
            TestOnIncorrectXml(client => Remote.GetS3Token(Username,
                                                           Token,
                                                           DeviceId,
                                                           Timestamp,
                                                           client),
                               SetupClientForPostWithAuth);
        }

        [Fact]
        public void FindLatestDbVersion_returns_version_from_s3()
        {
            var s3 = SetupS3(VersionInfo);

            Assert.Equal(Version, Remote.FindLatestDbVersion(Bucket, ObjectPrefix, s3.Object));
        }

        [Fact]
        public void FindLatestDbVersion_requests_file_from_s3()
        {
            var s3 = SetupS3(VersionInfo);
            Remote.FindLatestDbVersion(Bucket, ObjectPrefix, s3.Object);

            s3.Verify(x => x.GetObjectAsync(
                It.Is<string>(s => s == Bucket),
                It.Is<string>(s => s.Contains(ObjectPrefix) && s.Contains("spc.info")),
                It.IsAny<CancellationToken>()));
        }

        [Fact]
        public void FindLatestDbVersion_throws_on_network_error()
        {
            var s3 = SetupS3Error<WebException>();

            var e = Assert.Throws<FetchException>(
                () => Remote.FindLatestDbVersion(Bucket, ObjectPrefix, s3.Object));

            Assert.Equal(FetchException.FailureReason.NetworkError, e.Reason);
            Assert.IsType<WebException>(e.InnerException);
        }

        [Fact]
        public void FindLatestDbVersion_throws_on_aws_error()
        {
            var s3 = SetupS3Error<AmazonServiceException>();

            var e = Assert.Throws<FetchException>(
                () => Remote.FindLatestDbVersion(Bucket, ObjectPrefix, s3.Object));

            Assert.Equal(FetchException.FailureReason.S3Error, e.Reason);
            Assert.IsType<AmazonServiceException>(e.InnerException);
        }

        [Fact]
        public void FindLatestDbVersion_throws_on_invalid_format()
        {
            var responses = new[]
            {
                "",
                "   ",
                "\t\n",
                "VERSION\nMILESTONE\n"
            };

            foreach (var i in responses)
            {
                var s3 = SetupS3(i);
                var e = Assert.Throws<FetchException>(
                    () => Remote.FindLatestDbVersion(Bucket, ObjectPrefix, s3.Object));
                Assert.Equal(FetchException.FailureReason.InvalidResponse, e.Reason);
            }
        }

        [Fact]
        public void DownloadDb_returns_content_from_s3()
        {
            var s3 = SetupS3(CompressedDbContent);

            Assert.Equal(DbContent.ToBytes(), Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));
        }

        [Fact]
        public void DownloadDb_requests_file_from_s3()
        {
            var s3 = SetupS3(CompressedDbContent);
            Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object);

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
                () => Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));

            Assert.Equal(FetchException.FailureReason.NetworkError, e.Reason);
            Assert.IsType<WebException>(e.InnerException);
        }

        [Fact]
        public void DownloadDb_throws_on_aws_error()
        {
            var s3 = SetupS3Error<AmazonServiceException>();

            var e = Assert.Throws<FetchException>(
                () => Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));

            Assert.Equal(FetchException.FailureReason.S3Error, e.Reason);
            Assert.IsType<AmazonServiceException>(e.InnerException);
        }

        [Fact]
        public void DownloadDb_throws_on_invalid_deflated_content()
        {
            var s3 = SetupS3("Not really deflated");

            var e = Assert.Throws<FetchException>(
                () => Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object));
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
    }
}
