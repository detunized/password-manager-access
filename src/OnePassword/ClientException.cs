// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.OnePassword
{
    public class ClientException: BaseException
    {
        public enum FailureReason
        {
            IncorrectSecondFactorCode,
            OutdatedRememberMeToken,
            UserCanceledSecondFactor,
            UnsupportedFeature,
            InvalidOperation,
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
