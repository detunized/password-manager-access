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
            var securityToken = "securityToken";
            var bucketName = "bucketName";
            var objectPrefix = "objectPrefix";

            var token = new S3Token(accessKeyId, secretAccessKey, securityToken, bucketName, objectPrefix);

            Assert.Equal(accessKeyId, token.Credentials.AccessKeyId);
            Assert.Equal(secretAccessKey, token.Credentials.SecretAccessKey);
            Assert.Equal(securityToken, token.Credentials.SecurityToken);
            Assert.Equal(bucketName, token.BucketName);
            Assert.Equal(objectPrefix, token.ObjectPrefix);
        }
    }
}
