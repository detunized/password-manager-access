// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

//#define PROFILE_ENABLED

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace PasswordManagerAccess.Common
{
    internal static class Debug
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Measure(string name, Action f)
        {
#if PROFILE_ENABLED
            Measure(
                name,
                () =>
                {
                    f();
                    return 0;
                }
            );
#else
            f();
#endif
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static T Measure<T>(string name, Func<T> f)
        {
#if PROFILE_ENABLED
            var sw = new Stopwatch();
            sw.Start();
            try
            {
                return f();
            }
            finally
            {
                sw.Stop();
                Console.WriteLine($"{name}: {sw.Elapsed}");
            }
#else
            return f();
#endif
        }
    }
}
