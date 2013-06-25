using System;
using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            new Fetcher("username", "password").Login();
        }
    }
}
