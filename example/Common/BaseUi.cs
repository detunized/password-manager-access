// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Example.Common
{
    public abstract class BaseUi
    {
        protected const string PressEnterToCancel = "or just press ENTER to cancel";

        protected static string GetAnswer(string prompt)
        {
            Console.WriteLine(prompt);
            Console.Write("> ");
            var input = Console.ReadLine();

            return input == null ? "" : input.Trim();
        }

        protected static bool GetRememberMe()
        {
            var remember = GetAnswer("Remember this device?").ToLower();
            return remember == "y" || remember == "yes";
        }

        protected static void WriteLine(string text, ConsoleColor color)
        {
            Util.WriteLine(text, color);
        }
    }
}
