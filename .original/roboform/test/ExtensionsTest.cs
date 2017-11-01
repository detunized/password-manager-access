// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using RoboForm;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    public class ExtensionsTest
    {
        //
        // string
        //

        [Test]
        public void String_EscapeUri_escapes_special_characters()
        {
            var testCases = new Dictionary<string, string>
            {
                // TODO: Add more test cases to make sure it matches JS.
                {"", ""},
                {";,/?:@&=+$#", ";,/?:@&=+$#"},
                {"-_.!~*'()", "-_.!~*'()"},
                {"ABC abc 123", "ABC%20abc%20123"},
            };

            foreach (var i in testCases)
                Assert.That(i.Key.EncodeUri(), Is.EqualTo(i.Value));
        }
    }
}
