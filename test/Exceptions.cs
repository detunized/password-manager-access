// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Xunit;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Test
{
    internal static class Exceptions
    {
        public static BadCredentialsException AssertThrowsBadCredentials(Action action, string message = "")
        {
            return AssertThrows<BadCredentialsException>(action, message);
        }

        public static InternalErrorException AssertThrowsInternalError(Action action, string message = "")
        {
            return AssertThrows<InternalErrorException>(action, message);
        }

        private static T AssertThrows<T>(Action action, string message) where T: BaseException
        {
            var e = Assert.Throws<T>(action);
            Assert.NotNull(e.Message);
            Assert.Contains(message, e.Message);

            return e;
        }
    }
}
