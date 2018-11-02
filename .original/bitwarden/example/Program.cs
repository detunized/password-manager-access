// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using Bitwarden;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read Bitwarden credentials from a file
            // The file should contain 2 lines:
            //   - username
            //   - password
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];
        }
    }
}
