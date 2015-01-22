// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using PasswordBox;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read PasswordBox credentials from a file
            // The file should contain 2 lines: username and password.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            Console.WriteLine("Username: {0}", username);
            Console.WriteLine("Password: {0}", password);
        }
    }
}
