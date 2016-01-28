// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace Dashlane
{
    public static class Parser
    {
        public static byte[] ComputeEncryptionKey(string password, byte[] salt)
        {
            return new Rfc2898DeriveBytes(password, salt, 10204).GetBytes(32);
        }
    }
}
