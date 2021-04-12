// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading.Tasks;

namespace PasswordManagerAccess.Example.Common
{
    public abstract class BaseUi
    {
        protected const string PressEnterToCancel = "or just press ENTER to cancel";

        protected static string GetAnswer(string prompt) => GetAnswerAsync(prompt).GetAwaiter().GetResult();
        protected static bool GetRememberMe() => GetRememberMeAsync().GetAwaiter().GetResult();

        protected static async Task<string> GetAnswerAsync(string prompt)
        {
            Console.WriteLine(prompt);
            Console.Write("> ");
            var input = await Task.Run(() => Console.ReadLine());

            return input == null ? "" : input.Trim();
        }

        protected static async Task<bool> GetRememberMeAsync()
        {
            var remember = await GetAnswerAsync("Remember this device?");
            return remember.ToLower().StartsWith("y");
        }

        protected static void WriteLine(string text, ConsoleColor color)
        {
            Util.WriteLine(text, color);
        }
    }
}
