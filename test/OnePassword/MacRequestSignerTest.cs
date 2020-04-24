// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net.Http;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class MacRequestSignerTest
    {
        [Fact]
        public void Sign_returns_headers_with_signature()
        {
            var signature = Sign("https://my.1password.com/api/v1/auth/verify", HttpMethod.Post);

            Assert.Equal("v1|842346063|xv-fEAYowunpH4V-", signature);
        }

        [Fact]
        public void Sign_returns_signature_for_url_with_query()
        {
            var signature = Sign(
                "https://my.1password.com/api/v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults",
                HttpMethod.Get);

            Assert.Equal("v1|842346063|UyjKq0HAmjB5j7kF", signature);
        }

        [Fact]
        public void Sign_returns_differnt_results_next_time()
        {
            var signer = MakeSigner();
            var signature1 = Sign("https://my.1password.com/api/v1/auth/verify", HttpMethod.Post, signer);
            var signature2 = Sign("https://my.1password.com/api/v1/auth/verify", HttpMethod.Post, signer);

            Assert.NotEqual(signature1, signature2);
        }

        [Fact]
        public void Sign_increments_the_counter_by_one()
        {
            var signer = MakeSigner();
            var signature1 = Sign("https://my.1password.com/api/v1/auth/verify", HttpMethod.Post, signer);
            var signature2 = Sign("https://my.1password.com/api/v1/auth/verify", HttpMethod.Post, signer);

            var seed1 = uint.Parse(signature1.Split('|')[1]);
            var seed2 = uint.Parse(signature2.Split('|')[1]);

            Assert.Equal(seed1 + 1, seed2);
        }

        //
        // Helpers
        //

        private static MacRequestSigner MakeSigner()
        {
            // The test data is generated with the actual web page JS.
            var session = TestData.MakeSession("PBXONDZUWVCJFAV25C7XR7IYDQ");
            var key = new AesKey(session.Id, "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64Loose());
            var seed = 842346063u;

            return new MacRequestSigner(session, key, seed);
        }

        private static string Sign(string url, HttpMethod method, MacRequestSigner signer = null)
        {
            var headers = (signer ?? MakeSigner()).Sign(new Uri(url), method, NoHeaders);
            return Assert.Contains("X-AgileBits-MAC", headers);
        }

        //
        // Data
        //

        private static readonly Dictionary<string, string> NoHeaders = new Dictionary<string, string>();
    }
}
