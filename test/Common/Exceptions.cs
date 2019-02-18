// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Xunit;

namespace PasswordManagerAccess.Common
{
    internal static class Exceptions
    {
        public static ClientException AssertThrowsClientException(Action action)
        {
            var e = Record.Exception(action);

            Assert.NotNull(e);
            Assert.IsType<ClientException>(e);

            return (ClientException)e;
        }

        public static ClientException AssertThrowsClientException(Action action,
                                                                  ClientException.FailureReason reason,
                                                                  string message = "")
        {
            var e = AssertThrowsClientException(action, reason);

            Assert.NotNull(e.Message);
            Assert.Contains(message, e.Message);

            return e;
        }

        public static ClientException AssertThrowsInvalidResponse(Action action, string message = "")
        {
            return AssertThrowsClientException(action, ClientException.FailureReason.InvalidResponse, message);
        }
    }
}
