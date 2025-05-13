// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword;

internal class SrpInfo
{
    public readonly string SrpMethod;
    public readonly string KeyMethod;
    public readonly int Iterations;
    public readonly byte[] Salt;

    public SrpInfo(string srpMethod, string keyMethod, int iterations, byte[] salt)
    {
        SrpMethod = srpMethod;
        KeyMethod = keyMethod;
        Iterations = iterations;
        Salt = salt;
    }
}
