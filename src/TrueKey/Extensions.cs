// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;

namespace PasswordManagerAccess.TrueKey
{
    internal static class Extensions
    {
        //
        // uint
        //

        public static uint ChangeEndianness(this uint x)
        {
            return ((x & 0x000000FF) << 24) |
                   ((x & 0x0000FF00) <<  8) |
                   ((x & 0x00FF0000) >>  8) |
                   ((x & 0xFF000000) >> 24);
        }

        public static uint FromBigEndian(this uint x)
        {
            return BitConverter.IsLittleEndian ? x.ChangeEndianness() : x;
        }

        //
        // DateTime
        //

        public static uint UnixSeconds(this DateTime time)
        {
            const long secondsSinceEpoch = 62135596800;
            long seconds = time.ToUniversalTime().Ticks / TimeSpan.TicksPerSecond - secondsSinceEpoch;

            // TODO: This will stop working on January 19, 2038 03:14:07. Fix ASAP!
            return (uint)seconds;
        }
    }
}
