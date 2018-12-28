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
            IncorrectSecondFactorCode,
            UserCanceledSecondFactor,
            NetworkError,
            InvalidResponse,
            RespondedWithError,
            UnsupportedFeature,
            InvalidFormat,
            CryptoError,
        }

        public ClientException(FailureReason reason, string message, Exception innerException = null):
            base(message, innerException)
        {
            Reason = reason;
        }

        public FailureReason Reason { get; private set; }
    }
}
