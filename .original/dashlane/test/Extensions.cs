// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Text;

namespace Dashlane.Test
{
    internal static class Extensions
    {
        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }
    }
}
