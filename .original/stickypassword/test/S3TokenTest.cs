// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace StickyPassword.Test
{
    [TestFixture]
    class S3TokenTest
    {
        [Test]
        public void S3Token_properties_are_set()
        {
            var accessKeyId = "accessKeyId";
            var secretAccessKey = "secretAccessKey";
            var sessionToken = "sessionToken";
            var dateExpiration = "dateExpiration";
            var bucketName = "bucketName";
            var objectPrefix = "objectPrefix";

            var token = new S3Token(accessKeyId,
                                    secretAccessKey,
                                    sessionToken,
                                    dateExpiration,
                                    bucketName,
                                    objectPrefix);

            Assert.That(token.AccessKeyId, Is.EqualTo(accessKeyId));
            Assert.That(token.SecretAccessKey, Is.EqualTo(secretAccessKey));
            Assert.That(token.SessionToken, Is.EqualTo(sessionToken));
            Assert.That(token.DateExpiration, Is.EqualTo(dateExpiration));
            Assert.That(token.BucketName, Is.EqualTo(bucketName));
            Assert.That(token.ObjectPrefix, Is.EqualTo(objectPrefix));
        }
    }
}
