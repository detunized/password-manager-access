// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class S3TokenTest
    {
        [Fact]
        public void S3Token_properties_are_set()
        {
            var accessKeyId = "accessKeyId";
            var secretAccessKey = "secretAccessKey";
            var sessionToken = "sessionToken";
            var expirationDate = "expirationDate";
            var bucketName = "bucketName";
            var objectPrefix = "objectPrefix";

            var token = new S3Token(accessKeyId,
                                    secretAccessKey,
                                    sessionToken,
                                    expirationDate,
                                    bucketName,
                                    objectPrefix);

            Assert.Equal(accessKeyId, token.AccessKeyId);
            Assert.Equal(secretAccessKey, token.SecretAccessKey);
            Assert.Equal(sessionToken, token.SessionToken);
            Assert.Equal(expirationDate, token.ExpirationDate);
            Assert.Equal(bucketName, token.BucketName);
            Assert.Equal(objectPrefix, token.ObjectPrefix);
        }
    }
}
