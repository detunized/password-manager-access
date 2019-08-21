// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Dashlane
{
    public static class Uki
    {
        public static string Generate()
        {
            // This loosely mirrors the web uki generation process. Not clear if it's needed. Looks
            // like a simple random string does the job. Anyways...

            var time = DateTime.Now.Ticks/TimeSpan.TicksPerMillisecond;
            var text = string.Format(
                "{0}{1}{2:x8}",
                Environment.OSVersion.VersionString,
                time,
                (uint)((1 + new Random().NextDouble()) * 268435456));
            var hash = MD5.Create().ComputeHash(text.ToBytes()).ToHex();

            return string.Format("{0}-webaccess-{1}", hash, time);
        }
    }
}
