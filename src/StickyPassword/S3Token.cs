// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace StickyPassword
{
    public class S3Token
    {
        public S3Token(string accessKeyId,
                       string secretAccessKey,
                       string sessionToken,
                       string expirationDate,
                       string bucketName,
                       string objectPrefix)
        {
            AccessKeyId = accessKeyId;
            SecretAccessKey = secretAccessKey;
            SessionToken = sessionToken;
            ExpirationDate = expirationDate;
            BucketName = bucketName;
            ObjectPrefix = objectPrefix;
        }

        public string AccessKeyId { get; private set; }
        public string SecretAccessKey { get; private set; }
        public string SessionToken { get; private set; }
        public string ExpirationDate { get; private set; }
        public string BucketName { get; private set; }
        public string ObjectPrefix { get; private set; }
    }
}
