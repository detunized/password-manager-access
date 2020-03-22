// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.StickyPassword
{
    internal class S3Token
    {
        public readonly S3.Credentials Credentials;
        public readonly string BucketName;
        public readonly string ObjectPrefix;

        public S3Token(string accessKeyId,
                       string secretAccessKey,
                       string securityToken,
                       string bucketName,
                       string objectPrefix) : this(new S3.Credentials(accessKeyId: accessKeyId,
                                                                      secretAccessKey: secretAccessKey,
                                                                      securityToken: securityToken),
                                                   bucketName,
                                                   objectPrefix)
        {
        }

        public S3Token(S3.Credentials credentials, string bucketName, string objectPrefix)
        {
            Credentials = credentials;
            BucketName = bucketName;
            ObjectPrefix = objectPrefix;
        }
    }
}
