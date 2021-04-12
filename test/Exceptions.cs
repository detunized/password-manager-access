// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test
{
    internal static class Exceptions
    {
        public static BadCredentialsException AssertThrowsBadCredentials(Action action, string message = "") =>
            AssertThrows<BadCredentialsException>(action, message);

        public static async Task<BadCredentialsException> AssertThrowsBadCredentialsAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<BadCredentialsException>(action, message);

        public static BadMultiFactorException AssertThrowsBadMultiFactor(Action action, string message = "") =>
            AssertThrows<BadMultiFactorException>(action, message);

        public static async Task<BadMultiFactorException> AssertThrowsBadMultiFactorAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<BadMultiFactorException>(action, message);

        public static CanceledMultiFactorException AssertThrowsCanceledMultiFactor(Action action, string message = "") =>
            AssertThrows<CanceledMultiFactorException>(action, message);

        public static async Task<CanceledMultiFactorException> AssertThrowsCanceledMultiFactorAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<CanceledMultiFactorException>(action, message);

        public static NetworkErrorException AssertThrowsNetworkError(Action action, string message = "") =>
            AssertThrows<NetworkErrorException>(action, message);

        public static async Task<NetworkErrorException> AssertThrowsNetworkErrorAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<NetworkErrorException>(action, message);

        public static UnsupportedFeatureException AssertThrowsUnsupportedFeature(Action action, string message = "") =>
            AssertThrows<UnsupportedFeatureException>(action, message);

        public static async Task<UnsupportedFeatureException> AssertThrowsUnsupportedFeatureAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<UnsupportedFeatureException>(action, message);

        public static InternalErrorException AssertThrowsInternalError(Action action, string message = "") =>
            AssertThrows<InternalErrorException>(action, message);

        public static async Task<InternalErrorException> AssertThrowsInternalErrorAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<InternalErrorException>(action, message);

        public static CryptoException AssertThrowsCrypto(Action action, string message = "") =>
            AssertThrows<CryptoException>(action, message);

        public static async Task<CryptoException> AssertThrowsCryptoAsync(Func<Task> action, string message = "") =>
            await AssertThrowsAsync<CryptoException>(action, message);

        private static T AssertThrows<T>(Action action, string message) where T: BaseException
        {
            var e = Assert.Throws<T>(action);
            Assert.NotNull(e.Message);
            Assert.Contains(message, e.Message);

            return e;
        }

        private static async Task<T> AssertThrowsAsync<T>(Func<Task> action, string message) where T: BaseException
        {
            var e = await Assert.ThrowsAsync<T>(action);
            Assert.NotNull(e.Message);
            Assert.Contains(message, e.Message);

            return e;
        }
    }
}
