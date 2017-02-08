// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using Amazon.S3;
using Moq;
using NUnit.Framework;

namespace StickyPassword.Test
{
    [TestFixture]
    class RemoteTest
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
                    "<SessionToken>FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dhvf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF</SessionToken>" +
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

        [Test]
        public void GetEncryptedToken_makes_post_request()
        {
            var client = SetupClientForPost(GetTokenResponse);
            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.Verify(x => x.Post(
                It.Is<string>(s => s == "GetCrpToken"),
                It.Is<string>(s => s.Contains(DeviceId)),
                It.Is<DateTime>(d => d == Timestamp),
                It.Is<Dictionary<string, string>>(
                    d => d.ContainsKey("uaid") && d["uaid"] == Username)));
        }

        [Test]
        public void GetEncryptedToken_returns_response()
        {
            Assert.That(
                Remote.GetEncryptedToken(Username,
                                         DeviceId,
                                         Timestamp,
                                         SetupClientForPost(GetTokenResponse).Object),
                Is.EqualTo(EncryptedToken));
        }

        [Test]
        [ExpectedException(typeof(FetchException))]
        public void GetEncryptedToken_throws_on_non_zero_status()
        {
            Remote.GetEncryptedToken(Username,
                                     DeviceId,
                                     Timestamp,
                                     SetupClientForPost(ResponseWithError).Object);
        }

        [Test]
        public void GetEncryptedToken_throws_on_incorrect_xml()
        {
            TestOnIncorrectXml(client => Remote.GetEncryptedToken(Username,
                                                                  DeviceId,
                                                                  Timestamp,
                                                                  client),
                               SetupClientForPost);
        }

        [Test]
        public void AuthorizeDevice_works()
        {
            // TODO: Make this test verify something

            var client = SetupClientForPostWithAuth(AuthorizeDeviceResponse);
            Remote.AuthorizeDevice(Username, Token, DeviceId, DeviceName, Timestamp, client.Object);
        }

        [Test]
        [ExpectedException(typeof(FetchException))]
        public void AuthorizeDevice_throws_on_non_zero_status()
        {
            Remote.AuthorizeDevice(Username,
                                   Token,
                                   DeviceId,
                                   DeviceName,
                                   Timestamp,
                                   SetupClientForPostWithAuth(ResponseWithError).Object);
        }

        [Test]
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

        [Test]
        public void GetS3Token_returns_s3_token()
        {
            var client = SetupClientForPostWithAuth(GetS3TokenResponse);
            var s3 = Remote.GetS3Token(Username, Token, DeviceId, Timestamp, client.Object);

            Assert.That(s3.AccessKeyId, Is.EqualTo("ASIAIFIAL3EJEOPJXVCQ"));
            Assert.That(s3.SecretAccessKey, Is.EqualTo("TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d"));
            Assert.That(s3.SessionToken, Is.EqualTo("FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dhvf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF"));
            Assert.That(s3.ExpirationDate, Is.EqualTo("2017-01-11T12:24:24.000Z"));
            Assert.That(s3.BucketName, Is.EqualTo("spclouddata"));
            Assert.That(s3.ObjectPrefix, Is.EqualTo("31645cc8-6ae9-4a22-aaea-557efe9e43af/"));
        }

        [Test]
        [ExpectedException(typeof(FetchException))]
        public void GetS3Token_throws_on_non_zero_status()
        {
            Remote.GetS3Token(Username,
                              Token,
                              DeviceId,
                              Timestamp,
                              SetupClientForPostWithAuth(ResponseWithError).Object);
        }

        [Test]
        public void GetS3Token_throws_on_incorrect_xml()
        {
            TestOnIncorrectXml(client => Remote.GetS3Token(Username,
                                                           Token,
                                                           DeviceId,
                                                           Timestamp,
                                                           client),
                               SetupClientForPostWithAuth);
        }

        [Test]
        public void FindLastestDbVersion_returns_version_from_s3()
        {
            var s3 = SetupS3(VersionInfo);

            Assert.That(
                Remote.FindLastestDbVersion(Bucket, ObjectPrefix, s3.Object),
                Is.EqualTo(Version));
        }

        [Test]
        public void FindLastestDbVersion_requests_file_from_s3()
        {
            var s3 = SetupS3(VersionInfo);
            Remote.FindLastestDbVersion(Bucket, ObjectPrefix, s3.Object);

            s3.Verify(x => x.GetObject(
                It.Is<string>(s => s == Bucket),
                It.Is<string>(s => s.Contains(ObjectPrefix) && s.Contains("spc.info"))));
        }

        [Test]
        public void DownloadDb_returns_content_from_s3()
        {
            var s3 = SetupS3(CompressedDbContent);

            Assert.That(
                Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object),
                Is.EqualTo(DbContent.ToBytes()));
        }

        [Test]
        public void DownloadDb_requests_file_from_s3()
        {
            var s3 = SetupS3("");
            Remote.DownloadDb(Version, Bucket, ObjectPrefix, s3.Object);

            s3.Verify(x => x.GetObject(
                It.Is<string>(s => s == Bucket),
                It.Is<string>(s => s.Contains(ObjectPrefix) && s.Contains(Version))));
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

        private static Mock<IAmazonS3> SetupS3(string response)
        {
            return SetupS3(response.ToBytes());
        }

        private static Mock<IAmazonS3> SetupS3(byte[] response)
        {
            var s3 = new Mock<IAmazonS3>();
            s3
                .Setup(x => x.GetObject(It.IsAny<string>(), It.IsAny<string>()))
                .Returns(new Amazon.S3.Model.GetObjectResponse
                {
                    ResponseStream = new MemoryStream(response)
                });

            return s3;
        }

        public void TestOnIncorrectXml(Action<IHttpClient> what,
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
                Assert.That(() => what(setup(i).Object),
                            Throws.InvalidOperationException);
            }
        }
    }
}
