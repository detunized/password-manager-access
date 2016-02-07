// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read Dashlane credentials from a file
            // The file should contain 3 lines: username, password and uki.
            // The uki is optional.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            var uki = credentials.ElementAtOrDefault(2);
            if (string.IsNullOrWhiteSpace(uki))
                uki = "";

            Console.WriteLine("Got\nusername: {0}\npassword: {1}\nuki: {2}", username, password, uki);
        }
    }
}
