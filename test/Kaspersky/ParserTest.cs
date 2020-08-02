// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class ParserTest: TestBase
    {
        [Fact]
        public void ParseVault_returns_accounts()
        {
            var changes = XDocument.Parse(GetFixture("vault-response", "xml"))
                .XPathSelectElements("//*[starts-with(local-name(), 'item_')]")
                .Select(x => new Bosh.Change(x.Attribute("type").Value, x.Attribute("dataInBase64").Value));

            Parser.ParseVault(changes);
        }

        [Fact]
        public void DecryptItemVersion92_decrypts_item()
        {
            var blob = "AwAAAHja7Vdbc6pIEP4vvOakRAXEU5WHGRiJERRUSMjWqS2EAUZuyjWa8r8fyG5ysoZUadXZWmsr88Clp7/u5usZpvuZs" +
                       "vI8Jasixxn1/Y9nyrFyi/r+TK3CZPUicAkOnba5Ljtkej2aZXp9nv1G5bsNroWHb1RsRfVTo42VxCG1AYc6fDuGu1aY4V" +
                       "dY7xeMZCLepNiu0W2wPC3aUSi2093mTJBBMrIKcQuEbvmiEqcZSWLq8ONNFP1pJ1GE4/zFxIVx9TnsvyLLwa5VhLmceCT" +
                       "+YuwUxryCOF9MncIUsZOvNXUaUxko8sSyc1JaOfli7VTWRlaZpCTH/x++Pkf9FsIkHOO0CXjayC6QtYurJuILJerytuPG" +
                       "SuuyS0qTYiNd6Bl5caurSMMvnk7jCWw24W7ZaDczf8HYX7BNmmxwmhOcKTi3Xtyc6e/f3pm+lYm1opDE+Wt7ciKBMrFxn" +
                       "J2d4BCfmSjQFCD4LC+LXWz7aRKT/Xmu3uPekvrpLqBoEbE000XXiOHRNUP32GvID9G1KNC9LgBDBAcs9eqIPrSV68cW/x" +
                       "7XLZfX0W6x7T/324x/6MeOLEdppMwCj5b9K9XwOCGeaygfjB9mIVm6D3dw2N2P5YWapcqDVQbJfYDiUrGQat3Kt0wU6QW" +
                       "zlKaTcr3eFgQ+zhn+cRw42s3NWzT9Q9vh988o4iIMW/Xft95HgRMDzuYVPZG8BNRjutB9pHv1E2xegSYAs7m7fGfov0ge" +
                       "pos5PQZpxtic1gjmsaZ3a23haV2VvKnpjfDORv6jXQEgZkr9OhCB7ZRbqQEI+kKfQ0P0VfMKbiw3VAXLKoCdDjvuEJqqf" +
                       "BfsyISXpAzWIZExnflVptqe2uuvyr7a66SGr005SEpgo9QIINvpdFxXVaQ9cu5FfoxKE8w0YPrcDm3FWdofmLNJECEwQb" +
                       "QHuPFUk00DBgIk2wr7t8jywBPIyd1AmEdrCYjCYjd0vGgrAqny10z1JALoB1IfsR7OoC+o9x2mmQM4YaVZCcUXXlA4Wga" +
                       "LQosEoT1pb23XUQZmrJnQoy2ZF9vAXctKWATG4H7EArFm0ZNCutjzworIcFcsO7DiSpX0VQ7uc/So9HtjnjdZp2QLYc9B" +
                       "g1T9ACTTTliJc0GQsBKb3K292ju23zUG2ifL6fW0OwpsrpZOJrGok0yJP7EKcxLoOpRHm2UVZRF0ASsNLdm7c+HUNhB0X" +
                       "S4okkCccWNVSW93+ZWv6xwS781tOpIfB7qzZhZ5dfN5EO+OkpN/dR/ajdNhH4vu07HHfeGPw0+s9YS/";

            Parser.ParseItemVersion92(blob.Decode64());
        }
    }
}
