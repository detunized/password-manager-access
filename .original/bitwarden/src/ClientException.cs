// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace Bitwarden
{
    public class ClientException: BaseException
    {
        public enum FailureReason
        {
            IncorrectCredentials,
            NetworkError,
            InvalidResponse,
            RespondedWithError,
            UnsupportedFeature,
            InvalidFormat,
            InvalidOperation,
            CryptoError,
            UnknownError
        }

        public ClientException(FailureReason reason, string message):
            this(reason, message, null)
        {
        }

        public ClientException(FailureReason reason, string message, Exception innerException):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}