// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Numerics;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class SrpV1Test : TestBase
    {
        [Fact]
        public void ExchangeAForB_returns_B()
        {
            var b = PerformExchange("exchange-a-for-b-response");

            Assert.True(b > BigInteger.Zero);
            Assert.True(b.ToByteArray().Length >= 20);
        }

        [Fact]
        public void ExchangeAForB_makes_POST_request_to_specific_url()
        {
            var flow = new RestFlow().Post(GetFixture("exchange-a-for-b-response")).ExpectUrl("1password.com/api/v1/auth").ToRestClient(ApiUrl);

            SrpV1.ExchangeAForB(0, TestData.SessionId, flow);
        }

        [Fact]
        public void ExchangeAForB_throws_on_mismatching_session_id()
        {
            Exceptions.AssertThrowsInternalError(() => PerformExchange("exchange-a-for-b-response", "incorrect-session-id"), "ID doesn't match");
        }

        [Fact]
        public void ComputeKey_returns_key()
        {
            var secretA = new BigInteger(1337);
            var sharedA = (
                "015600A0C9AEEB2077D805DF00DC3100B0121C15EB86B2E548829CF5BBD9DA7BA9"
                + "9C6561750E2C3CA2F3CF4D9FBB06564D1E324991E4003C67B9555D21918A46C061"
                + "87DFECC4D8D9FC951870B1E155D961571B7012D9A333019AFA4D7F8B1FF5CECB1F"
                + "60A1B157BADF03A5DE83AD5C2D9496AC70E2911BCFC8D7295ABB001B1143966EE0"
                + "956141801822332CEEF38BBE7A1A179900DD5CD9233E343835F6DF016E6E48691B"
                + "D3CA290556992F2A561507B7210DE8332F455DD80F1FDFC2F17DCF4659563C9F8D"
                + "E14884932E7D42F5C0FDD5C969FA3D83E40B112BA8CBB3D4D11304F16DA560E9B8"
                + "FA4CCD4D77B6EA849DF5BC0F10D4BEEF9F6AB6504BFADDE46B7FC7A199773701E7"
                + "632549CCAA4B92B2C802A2B8EEB2F7A65AF28BD72CE4A24916FB0902C05021C2CC"
                + "BAA173AA905F14656425902A9EF134A8ABA7B016D3A0A246597887550876EDFD9C"
                + "4D0DF89F3F6FA1CEC25428C736243E2A5CBC9C3EDD898306F01274C4438844E9DD"
                + "F8A2CC25029C84644F318B71C1A4C6595A7F0BBE1BCCF1C6DDA5"
            ).ToBigInt();

            var sharedB = (
                "37324A654B7493EA3C71D7A8B6B7E7E5E9040A3B13DFA72154CCAD13276E4CF402"
                + "869F13FDE2F7C4C9D8B829BA15C1699B14728DFFF45358C67932D5BDB8D0A311F5"
                + "4822C743E5549130F843EE9BE65EC3455ED50B1779928FD112074078CEEE141C98"
                + "148E6EB657ABEB4EB77796197279E05A5FA7776AE4DC8066E4C5852847126FC030"
                + "CD4AF6CF808CCAB07DAC5E477735132BAD29290C165253BC9502108F2B42469683"
                + "5670A24B6CFD5B2EAD23569E8B1149056800FCC0F20819D1571A4B95FBA0F3E516"
                + "D3256636F14F8E748D8630279651352B02A6544D431A863A086F37089414FD69DA"
                + "3857435E4205DCDA863761A08620A5D24D15BDB3B22C495E452EEBAD7F6F0F76A0"
                + "73DFCD6ADAC85A7F1506EFBA7D704AF812E4412BE0B3E9937D65EFAECF9D2B1789"
                + "08FF2EB9EECCF297441FC4E701D4F2B49B21A72B37E0BFD4E56C27D8B4792EEB50"
                + "FF453DA49229699A061DCCB7622F7C6C0BF6D1B01BC79B7DDC8848550C87D6EBF1"
                + "E3A0317BD33C502FFBF96D5A2F56A10BCAF842B6625B7D8CC0E489887305A107A6"
                + "A51E8565967F66C78C47F25D4249F4B46D93556C437664D0464EC0BA4697A78DA1"
                + "E8393396CC190C1547D469254A0A492901D922E8138D0F64F23B2CC5AFE833EAD9"
                + "241A3F1BD0A76ACF32F07ADFAB36A4784781DA7E87FA6EBDF2C008DF3C55F9E002"
                + "4D275C4D5C55A866D888E7AD4DE67D1E77"
            ).ToBigInt();

            var key = SrpV1.ComputeKey(secretA, sharedA, sharedB, TestData.Credentials, TestData.SrpInfo, TestData.SessionId);

            Assert.Equal("2vPT1GStqTBzGaU7hDrW8XfFjk2VyI6KOtYvgmxKWFo".Decode64Loose(), key);
        }

        [Fact]
        public void ComputeX_returns_X()
        {
            const string expected = "104882354933197857481625453411657638660079750214611069684" + "692024916274069892339";
            var x = SrpV1.ComputeX(TestData.Credentials, TestData.SrpInfo);

            Assert.Equal(expected, x.ToString());
        }

        //
        // Helpers
        //

        private BigInteger PerformExchange(string fixtureName, string sessionId = TestData.SessionId)
        {
            var flow = new RestFlow().Post(GetFixture(fixtureName)).ToRestClient(ApiUrl);

            return SrpV1.ExchangeAForB(0, sessionId, flow);
        }

        //
        // Data
        //

        private const string ApiUrl = "https://my.1password.com/api";
    }
}
