// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.Example.Common
{
    public abstract class BaseAsyncUi
    {
        public const string PressEnterToCancel = "or just press ENTER to cancel";

        public static async Task<string> GetAnswer(string prompt, CancellationToken cancellationToken)
        {
            Console.WriteLine(prompt + "\n> ");

#if NET8_0_OR_GREATER
            var input = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
#else
            var input = await Console.In.ReadLineAsync().ConfigureAwait(false);
#endif

            return input == null ? "" : input.Trim();
        }

        public static async Task<bool> GetRememberMe(CancellationToken cancellationToken)
        {
            var remember = (await GetAnswer("Remember this device?", cancellationToken).ConfigureAwait(false)).ToLower();
            return remember == "y" || remember == "yes";
        }

        public static void WriteLine(string text, ConsoleColor color) => Util.WriteLine(text, color);
    }

    // TODO: Remove this once done with the migration
    public abstract class BaseUi
    {
        public const string PressEnterToCancel = BaseAsyncUi.PressEnterToCancel;

        public static string GetAnswer(string prompt) => BaseAsyncUi.GetAnswer(prompt, CancellationToken.None).GetAwaiter().GetResult();

        public static bool GetRememberMe() => BaseAsyncUi.GetRememberMe(CancellationToken.None).GetAwaiter().GetResult();

        public static void WriteLine(string text, ConsoleColor color) => BaseAsyncUi.WriteLine(text, color);
    }
}
