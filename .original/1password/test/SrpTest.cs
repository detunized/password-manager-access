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
            var a = Srp.GenerateSecretA();
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
            var a = Srp.ComputeSharedA(1337);
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
        public void ExchangeAForB_throws_on_mismatching_session_id()
        {
            Assert.That(() => PerformExchange("exchange-a-for-b-response", "incorrect-session-id"),
                        Throws.TypeOf<ClientException>()
                            .And.Property("Reason")
                            .EqualTo(ClientException.FailureReason.InvalidOperation)
                            .And.Message.Contains("ID doesn't match"));
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

            Assert.That(() => Srp.ValidateB(b),
                        Throws.TypeOf<ClientException>()
                            .And.Property("Reason")
                            .EqualTo(ClientException.FailureReason.InvalidOperation)
                            .And.Message.Contains("validation failed"));
        }

        [Test]
        public void ComputeKey_returns_key()
        {
            var secretA = new BigInteger(1337);
            var sharedA = ("015600A0C9AEEB2077D805DF00DC3100B0121C15EB86B2E548829CF5BBD9DA7BA9" +
                           "9C6561750E2C3CA2F3CF4D9FBB06564D1E324991E4003C67B9555D21918A46C061" +
                           "87DFECC4D8D9FC951870B1E155D961571B7012D9A333019AFA4D7F8B1FF5CECB1F" +
                           "60A1B157BADF03A5DE83AD5C2D9496AC70E2911BCFC8D7295ABB001B1143966EE0" +
                           "956141801822332CEEF38BBE7A1A179900DD5CD9233E343835F6DF016E6E48691B" +
                           "D3CA290556992F2A561507B7210DE8332F455DD80F1FDFC2F17DCF4659563C9F8D" +
                           "E14884932E7D42F5C0FDD5C969FA3D83E40B112BA8CBB3D4D11304F16DA560E9B8" +
                           "FA4CCD4D77B6EA849DF5BC0F10D4BEEF9F6AB6504BFADDE46B7FC7A199773701E7" +
                           "632549CCAA4B92B2C802A2B8EEB2F7A65AF28BD72CE4A24916FB0902C05021C2CC" +
                           "BAA173AA905F14656425902A9EF134A8ABA7B016D3A0A246597887550876EDFD9C" +
                           "4D0DF89F3F6FA1CEC25428C736243E2A5CBC9C3EDD898306F01274C4438844E9DD" +
                           "F8A2CC25029C84644F318B71C1A4C6595A7F0BBE1BCCF1C6DDA5").ToBigInt();

            var sharedB = ("37324A654B7493EA3C71D7A8B6B7E7E5E9040A3B13DFA72154CCAD13276E4CF402" +
                           "869F13FDE2F7C4C9D8B829BA15C1699B14728DFFF45358C67932D5BDB8D0A311F5" +
                           "4822C743E5549130F843EE9BE65EC3455ED50B1779928FD112074078CEEE141C98" +
                           "148E6EB657ABEB4EB77796197279E05A5FA7776AE4DC8066E4C5852847126FC030" +
                           "CD4AF6CF808CCAB07DAC5E477735132BAD29290C165253BC9502108F2B42469683" +
                           "5670A24B6CFD5B2EAD23569E8B1149056800FCC0F20819D1571A4B95FBA0F3E516" +
                           "D3256636F14F8E748D8630279651352B02A6544D431A863A086F37089414FD69DA" +
                           "3857435E4205DCDA863761A08620A5D24D15BDB3B22C495E452EEBAD7F6F0F76A0" +
                           "73DFCD6ADAC85A7F1506EFBA7D704AF812E4412BE0B3E9937D65EFAECF9D2B1789" +
                           "08FF2EB9EECCF297441FC4E701D4F2B49B21A72B37E0BFD4E56C27D8B4792EEB50" +
                           "FF453DA49229699A061DCCB7622F7C6C0BF6D1B01BC79B7DDC8848550C87D6EBF1" +
                           "E3A0317BD33C502FFBF96D5A2F56A10BCAF842B6625B7D8CC0E489887305A107A6" +
                           "A51E8565967F66C78C47F25D4249F4B46D93556C437664D0464EC0BA4697A78DA1" +
                           "E8393396CC190C1547D469254A0A492901D922E8138D0F64F23B2CC5AFE833EAD9" +
                           "241A3F1BD0A76ACF32F07ADFAB36A4784781DA7E87FA6EBDF2C008DF3C55F9E002" +
                           "4D275C4D5C55A866D888E7AD4DE67D1E77").ToBigInt();

            var key = Srp.ComputeKey(secretA,
                                     sharedA,
                                     sharedB,
                                     TestData.ClientInfo,
                                     TestData.Session);

            Assert.That(key, Is.EqualTo("2vPT1GStqTBzGaU7hDrW8XfFjk2VyI6KOtYvgmxKWFo".Decode64()));
        }

        [Test]
        public void ComputeX_returns_X()
        {
            const string expected = "104882354933197857481625453411657638660079750214611069684" +
                                    "692024916274069892339";
            var x = Srp.ComputeX(TestData.ClientInfo, TestData.Session);

            Assert.That(x.ToString(), Is.EqualTo(expected));
        }

        //
        // Helpers
        //

        private static BigInteger PerformExchange(string fixture,
                                                  string sessionId = TestData.SessionId)
        {
            return Srp.ExchangeAForB(0, TestData.MakeSession(sessionId), SetupJsonHttp(fixture));
        }

        private static JsonHttpClient SetupJsonHttp(string fixture)
        {
            return new JsonHttpClient(JsonHttpClientTest.SetupPostWithFixture(fixture).Object, "");
        }
    }
}
