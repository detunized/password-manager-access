// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Text;

namespace StickyPassword
{
    internal static class Extensions
    {
        //
        // string
        //

        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] Decode64(this string s)
        {
            return Convert.FromBase64String(s);
        }

        //
        // byte[]
        //

        public static string ToUtf8(this byte[] x)
        {
            return Encoding.UTF8.GetString(x);
        }

        public static string Encode64(this byte[] x)
        {
            return Convert.ToBase64String(x);
        }

        //
        // Stream
        //

        public static byte[] ReadAll(this Stream stream, uint bufferSize = 4096)
        {
            if (bufferSize < 1)
                throw new ArgumentOutOfRangeException("bufferSize", "Buffer size must be positive");

            var buffer = new byte[bufferSize];
            using (var memoryStream = new MemoryStream())
            {
                int bytesRead;
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    memoryStream.Write(buffer, 0, bytesRead);

                return memoryStream.ToArray();
            }

        }
    }
}
