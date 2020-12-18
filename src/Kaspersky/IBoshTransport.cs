// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal interface IBoshTransport: IDisposable
    {
        Exception? Connect(string url);
        Try<string> Request(string body);
    }
}
