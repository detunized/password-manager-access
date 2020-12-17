// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;

namespace PasswordManagerAccess.Common
{
    internal static class Try
    {
        public static Try<T> FromValue<T>(T value) => Try<T>.FromValue(value);
        public static Try<T> FromError<T>(Exception error) => Try<T>.FromError(error);
        public static Try<T> FromError<T>(string message, Exception? inner = null) => Try<T>.FromError(message, inner);
    }

    internal readonly struct Try<T>
    {
        public T Value => IsValue ? _value : throw _error!;
        public Exception? Error => _error;

        public bool IsError => Error != null;
        public bool IsValue => Error == null;

        public static Try<T> FromValue(T value) => new Try<T>(value);
        public static Try<T> FromError(Exception error) => new Try<T>(error);
        public static Try<T> FromError(string message, Exception? inner = null) => FromError(MakeError(message, inner));

        public Try(T value)
        {
            _error = null;
            _value = value;
        }

        public Try(Exception error)
        {
            _error = error;
            _value = default!;
        }

        //
        // Private
        //

        private static Exception MakeError(string message, Exception? inner)
            => new InternalErrorException(message, inner);

        private readonly T _value;
        private readonly Exception? _error;
    }
}
