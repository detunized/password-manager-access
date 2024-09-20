// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Duo;

namespace PasswordManagerAccess.Example.Common
{
    public class DuoUi : BaseUi, IDuoUi
    {
        public DuoChoice ChooseDuoFactor(DuoDevice[] devices)
        {
            var prompt = $"Choose a factor you want to use {PressEnterToCancel}:\n\n";
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
            return GetAnswer($"Enter the passcode for {device.Name} {PressEnterToCancel}");
        }

        public void UpdateDuoStatus(DuoStatus status, string text)
        {
            WriteLine($"Duo {status}: {text}", StatusToColor(status));
        }

        private static ConsoleColor StatusToColor(DuoStatus status)
        {
            switch (status)
            {
                case DuoStatus.Success:
                    return ConsoleColor.Green;
                case DuoStatus.Error:
                    return ConsoleColor.Red;
                case DuoStatus.Info:
                    return ConsoleColor.Blue;
            }

            throw new ArgumentException("Unknown status");
        }
    }
}
