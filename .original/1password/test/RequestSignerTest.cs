// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class RequestSignerTest
    {
        [Test]
        public void Sign_returns_signature()
        {
            var signature = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "post");

            Assert.That(signature.Key, Is.EqualTo("X-AgileBits-MAC"));
            Assert.That(signature.Value, Is.EqualTo("v1|842346063|xv-fEAYowunpH4V-"));
        }

        [Test]
        public void Sign_returns_signature_for_url_with_query()
        {
            var signature = MakeSigner().Sign(
                "https://my.1password.com/api/v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults",
                "get");

            Assert.That(signature.Key, Is.EqualTo("X-AgileBits-MAC"));
            Assert.That(signature.Value, Is.EqualTo("v1|842346063|UyjKq0HAmjB5j7kF"));
        }

        [Test]
        public void Sign_ignores_case_on_method()
        {
            var signature1 = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "post");
            var signature2 = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "pOSt");
            var signature3 = MakeSigner().Sign("https://my.1password.com/api/v1/auth/verify", "POST");

            Assert.That(signature1.Value, Is.EqualTo("v1|842346063|xv-fEAYowunpH4V-"));
            Assert.That(signature2.Value, Is.EqualTo("v1|842346063|xv-fEAYowunpH4V-"));
            Assert.That(signature3.Value, Is.EqualTo("v1|842346063|xv-fEAYowunpH4V-"));
        }

        [Test]
        public void Sign_returns_differnt_results_next_time()
        {
            var signer = MakeSigner();
            var signature1 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");
            var signature2 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");

            Assert.That(signature1.Value, Is.Not.EqualTo(signature2));
        }

        [Test]
        public void Sign_increments_the_counter_by_one()
        {
            var signer = MakeSigner();
            var signature1 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");
            var signature2 = signer.Sign("https://my.1password.com/api/v1/auth/verify", "post");

            var seed1 = uint.Parse(signature1.Value.Split('|')[1]);
            var seed2 = uint.Parse(signature2.Value.Split('|')[1]);

            Assert.That(seed2, Is.EqualTo(seed1 + 1));
        }

        //
        // Helpers
        //

        private static RequestSigner MakeSigner()
        {
            // The test data is generated with the actual web page JS.
            var session = TestData.MakeSession("PBXONDZUWVCJFAV25C7XR7IYDQ");
            var key = new AesKey(session.Id,
                                 "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64());
            var seed = 842346063u;

            return new RequestSigner(session, key, seed);
        }
    }
}
