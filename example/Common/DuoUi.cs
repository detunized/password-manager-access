// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Example.Common
{
    public class DuoUi: IDuoUi
    {
        public DuoChoice ChooseDuoFactor(DuoDevice[] devices)
        {
            var prompt = $"Choose a factor you want to use {ToCancel}:\n\n";
            var index = 1;
            foreach (var d in devices)
            {
                prompt += $"{d.Name}\n";
                foreach (var f in d.Factors)
                {
                    prompt += $"  {index}. {f}\n";
                    index += 1;
                }
            }

            while (true)
            {
                var answer = GetAnswer(prompt);

                // Blank means canceled by the user
                if (string.IsNullOrWhiteSpace(answer))
                    return null;

                int choice;
                if (int.TryParse(answer, out choice))
                    foreach (var d in devices)
                    foreach (var f in d.Factors)
                        if (--choice == 0)
                            return new DuoChoice(d, f, GetRememberMe());

                Console.WriteLine("Wrong input, try again");
            }
        }

        public string ProvideDuoPasscode(DuoDevice device)
        {
            return GetAnswer($"Enter the passcode for {device.Name} {ToCancel}");
        }

        public void UpdateDuoStatus(DuoStatus status, string text)
        {
            switch (status)
            {
            case DuoStatus.Success:
                Console.ForegroundColor = ConsoleColor.Green;
                break;
            case DuoStatus.Error:
                Console.ForegroundColor = ConsoleColor.Red;
                break;
            case DuoStatus.Info:
                Console.ForegroundColor = ConsoleColor.Blue;
                break;
            }

            Console.WriteLine($"Duo {status}: {text}");
            Console.ResetColor();
        }

        //
        // Protected
        //

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

        protected const string ToCancel = "or just press ENTER to cancel";
    }
}
