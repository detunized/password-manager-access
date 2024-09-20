// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using OtpNet;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Example.Common
{
    public static class Util
    {
        // Look for config.yaml starting form current directory and up to 4 levels and then load it
        public static Dictionary<string, string> ReadConfig()
        {
            var filename = FindFile("config.yaml", 3);
            if (filename == null)
                throw new InvalidOperationException("config.yaml not found");

            return ReadConfig(filename);
        }

        // Read YAML-like config. Example:
        // username: dude
        // password: farout
        // url: https://lebowski.com
        public static Dictionary<string, string> ReadConfig(string filename)
        {
            return File.ReadAllLines(filename)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith("#"))
                .Select(line => line.Split(new[] { ':' }, 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0].Trim(), parts => parts[1].Trim());
        }

        public static string FindFile(string basename, int levelsUp)
        {
            var filename = basename;
            for (int i = 0; i <= levelsUp; ++i)
            {
                if (File.Exists(filename))
                    return filename;

                filename = $"../{filename}";
            }

            return null;
        }

        public static void PrintException(BaseException e)
        {
            var color = Console.ForegroundColor;

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(e.Message);
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine(e.StackTrace);
            Console.ForegroundColor = color;
        }

        public static void WriteLine(string text, ConsoleColor color)
        {
            var originalColor = Console.ForegroundColor;
            try
            {
                Console.ForegroundColor = color;
                Console.WriteLine(text);
            }
            finally
            {
                Console.ForegroundColor = originalColor;
            }
        }

        public static string CalculateGoogleAuthTotp(string secret)
        {
            return CalculateGoogleAuthTotp(secret, DateTime.UtcNow);
        }

        public static string CalculateGoogleAuthTotp(string secret, DateTime timestamp)
        {
            return new Totp(Base32Encoding.ToBytes(secret)).ComputeTotp(timestamp);
        }
    }
}
