// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test
{
    internal static class Exceptions
    {
        public static BadCredentialsException AssertThrowsBadCredentials(Action action, string message = "")
        {
            return AssertThrows<BadCredentialsException>(action, message);
        }

        public static BadMultiFactorException AssertThrowsBadMultiFactor(Action action, string message = "")
        {
            return AssertThrows<BadMultiFactorException>(action, message);
        }

        public static CanceledMultiFactorException AssertThrowsCanceledMultiFactor(Action action, string message = "")
        {
            return AssertThrows<CanceledMultiFactorException>(action, message);
        }

        public static CanceledSsoLoginException AssertThrowsCanceledSsoLogin(Action action, string message = "")
        {
            return AssertThrows<CanceledSsoLoginException>(action, message);
        }

        public static NetworkErrorException AssertThrowsNetworkError(Action action, string message = "")
        {
            return AssertThrows<NetworkErrorException>(action, message);
        }

        public static UnsupportedFeatureException AssertThrowsUnsupportedFeature(Action action, string message = "")
        {
            return AssertThrows<UnsupportedFeatureException>(action, message);
        }

        public static InternalErrorException AssertThrowsInternalError(Action action, string message = "")
        {
            return AssertThrows<InternalErrorException>(action, message);
        }

        public static CryptoException AssertThrowsCrypto(Action action, string message = "")
        {
            return AssertThrows<CryptoException>(action, message);
        }

        public static T AssertThrows<T>(Action action, string message)
            where T : Exception
        {
            var e = Assert.Throws<T>(action);
            Assert.NotNull(e.Message);
            Assert.Contains(message, e.Message);

            return e;
        }
    }
}
