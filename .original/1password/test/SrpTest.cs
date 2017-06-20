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

        [Test]
        public void ValidateB_throws_on_failed_validation()
        {
            var b = ("0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA" +
                     "63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C24" +
                     "5E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F241" +
                     "17C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5" +
                     "F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C0" +
                     "8CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C" +
                     "9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170" +
                     "D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C" +
                     "7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D876027" +
                     "33EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3" +
                     "143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C3271" +
                     "86AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA" +
                     "6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD7" +
                     "62170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93406319" +
                     "9FFFFFFFFFFFFFFFF").ToBigInt();

            Assert.That(() => new Srp(null).ValidateB(b), Throws.TypeOf<InvalidOperationException>());
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
            return SetupSrpForExchange(fixture).ExchangeAForB(0, MakeSession(sessionId));
        }

        private static Srp SetupSrpForExchange(string fixture)
        {
            var http = JsonHttpClientTest.SetupPostWithFixture(fixture);
            return new Srp(new JsonHttpClient(http.Object, ""));
        }

        private static Session MakeSession(string id)
        {
            return new Session(id: id,
                               keyFormat: "A3",
                               keyUuid: "FRN8GF",
                               srpMethod: "SRPg-4096",
                               keyMethod: "PBES2g-HS256",
                               iterations: 100000,
                               salt: "-JLqTVQLjQg08LWZ0gyuUA".Decode64());
        }
    }
}
