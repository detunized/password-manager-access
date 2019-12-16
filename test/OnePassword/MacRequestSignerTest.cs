// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class MacRequestSignerTest
    {
        [Fact]
        public void Sign_returns_signature()
        {
            var signature = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "post");

            Assert.Equal("X-AgileBits-MAC", signature.Key);
            Assert.Equal("v1|842346063|xv-fEAYowunpH4V-", signature.Value);
        }

        [Fact]
        public void Sign_returns_signature_for_url_with_query()
        {
            var signature = MakeSigner().Sign(
                "https://my.1password.com/api/v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults",
                "get");

            Assert.Equal("X-AgileBits-MAC", signature.Key);
            Assert.Equal("v1|842346063|UyjKq0HAmjB5j7kF", signature.Value);
        }

        [Fact]
        public void Sign_ignores_case_on_method()
        {
            var signature1 = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "post");
            var signature2 = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "pOSt");
            var signature3 = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "POST");

            Assert.Equal("v1|842346063|xv-fEAYowunpH4V-", signature1.Value);
            Assert.Equal("v1|842346063|xv-fEAYowunpH4V-", signature2.Value);
            Assert.Equal("v1|842346063|xv-fEAYowunpH4V-", signature3.Value);
        }

        [Fact]
        public void Sign_returns_differnt_results_next_time()
        {
            var signer = MakeSigner();
            var signature1 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");
            var signature2 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");

            Assert.NotEqual(signature1.Value, signature2.Value);
        }

        [Fact]
        public void Sign_increments_the_counter_by_one()
        {
            var signer = MakeSigner();
            var signature1 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");
            var signature2 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");

            var seed1 = uint.Parse(signature1.Value.Split('|')[1]);
            var seed2 = uint.Parse(signature2.Value.Split('|')[1]);

            Assert.Equal(seed1 + 1, seed2);
        }

        //
        // Helpers
        //

        private static MacRequestSigner MakeSigner()
        {
            // The test data is generated with the actual web page JS.
            var session = TestData.MakeSession("PBXONDZUWVCJFAV25C7XR7IYDQ");
            var key = new AesKey(session.Id,
                                 "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64());
            var seed = 842346063u;

            return new MacRequestSigner(session, key, seed);
        }
    }
}
