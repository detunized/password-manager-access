// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Common
{
    // This is an IDisposable wrapper for any regular non-disposable class so it could be
    // assigned to "using var" variable. It could be used to mix disposable and regular objects.
    // For example:
    // using IDisposable obj = isRegular ? new Indisposable<Regular>(new Regular()) : new Disposable();
    internal readonly struct Indisposable<T> : IDisposable
    {
        public T Value { get; }

        public Indisposable(T t)
        {
            Value = t;
        }

        public static implicit operator T(Indisposable<T> i) => i.Value;

        public void Dispose()
        {
            // Nothing to dispose of
        }
    }
}
