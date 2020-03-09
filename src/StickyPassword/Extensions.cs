// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;

namespace PasswordManagerAccess.StickyPassword
{
    internal static class Extensions
    {
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
