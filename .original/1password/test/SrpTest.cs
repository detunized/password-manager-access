// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Numerics;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class SrpTest
    {
        [Test]
        public void GenerateSecretA_returns_a_large_number()
        {
            var a = new Srp(null).GenerateSecretA();
            Assert.That(a.ToByteArray().Length, Is.AtLeast(20));
        }

        [Test]
        public void ComputeSharedA_returns_shared_A()
        {
            const string expected = "333346421466140763410769085841921229531670575226192261465" +
                                    "166542038394746516243180491569655653486434870673853537000" +
                                    "973992597570354051597770294140220366446603444498345701377" +
                                    "499538199323933346907452641835713662528809414994534663330" +
                                    "164380558635731566266605196918923802498675669312823978717" +
                                    "640217564431239355348935151043276108440702543161313560730" +
                                    "743541628554811981897201682697886750810044295984695444979" +
                                    "935047706027939298548755006138404269391302315458261363029" +
                                    "628849862314847159288779865624078138096539662948640714183" +
                                    "012861029325042832023769592096656858318625176405015058317" +
                                    "782134946143225960898512545826456047235745112565120740872" +
                                    "236482975683249097108881695460595417077854411232375010263" +
                                    "439844874684830265812040719304630647945775397473557106481" +
                                    "105152808274070381648534725506031377872191377676080425348" +
                                    "781921655911450853546924160841246493678732375446547730518" +
                                    "918881443743873444606149630727602090800656964297843387612" +
                                    "37449944019317626953125";
            var a = new Srp(null).ComputeSharedA(1337);
            Assert.That(a.ToString(), Is.EqualTo(expected));
        }

        [Test]
        public void ExchangeAForB_returns_B()
        {
            var b = PerformExchange("exchange-a-for-b-response");

            Assert.That(b, Is.GreaterThan(BigInteger.Zero));
            Assert.That(b.ToByteArray().Length, Is.AtLeast(20));
        }

        [Test]
        public void ExchangeAForB_handles_number_with_leading_ff()
        {
            var b = PerformExchange("exchange-a-for-b-with-ff-response");

            Assert.That(b, Is.GreaterThan(BigInteger.Zero));
            Assert.That(b.ToByteArray().Length, Is.AtLeast(20));
        }

        [Test]
        public void ExchangeAForB_throws_on_mismatching_session_id()
        {
            Assert.That(() => PerformExchange("exchange-a-for-b-response", "incorrect-session-id"),
                        Throws.TypeOf<InvalidOperationException>());
        }

        //
        // Data
        //

        private const string SessionId = "TOZVTFIFBZGFDFNE5KSZFY7EZY";


        //
        // Helpers
        //

        private static BigInteger PerformExchange(string fixture, string sessionId = SessionId)
        {
            return SetupSrpForExchange(fixture).ExchangeAForB(0, new Session(sessionId));
        }

        private static Srp SetupSrpForExchange(string fixture)
        {
            var http = JsonHttpClientTest.SetupPostWithFixture(fixture);
            return new Srp(new JsonHttpClient(http.Object, ""));
        }
    }
}
