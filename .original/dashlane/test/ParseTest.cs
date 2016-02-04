// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Xml.Linq;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class ParseTest
    {
        private const string Password = "password";
        private static readonly byte[] Salt = "saltsaltsaltsaltsaltsaltsaltsalt".ToBytes();
        private static readonly byte[] Content = "All your base are belong to us".ToBytes();

        [Test]
        public void ComputeEncryptionKey_returns_correct_result()
        {
            var key = Parse.ComputeEncryptionKey(Password, Salt);
            Assert.That(key, Is.EqualTo("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64()));
        }

        [Test]
        public void Sha1_computes_sha1_given_times()
        {
            var check = new Action<int, string>((iterations, expected) =>
                Assert.That(Parse.Sha1(Content, iterations), Is.EqualTo(expected.Decode64())));

            check(0, Convert.ToBase64String(Content));
            check(1, "xgmXgTCENlJpbnSLucn3NwPXkIk=");
            check(5, "RqcjtwJ5KY1MON7n3WwvqGhrrpg=");
        }

        [Test]
        public void DeriveEncryptionKeyAndIv_computes_key_and_iv_for_given_number_of_iterations()
        {
            var key = "OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64();
            var check = new Action<int, string, string>((iterations, expectedKey, expectedIv) =>
            {
                var keyIv = Parse.DeriveEncryptionKeyAndIv(key, Salt, iterations);
                Assert.That(keyIv.Key, Is.EqualTo(expectedKey.Decode64()));
                Assert.That(keyIv.Iv, Is.EqualTo(expectedIv.Decode64()));
            });

            check(1, "6HA2Rq9GTeKzAc1imNjvyaXBGW4zRA5wIr60Vbx/o8w=", "fCk2EkpIYGn05JHcVfR8eQ==");
            check(5, "fsuGfEOoYL4uOmp24ZuAExIuVePh6YIu7t0rfCDogpM=", "/vsHfrsRzyGCQOBP4UEQuw==");
        }

        [Test]
        public void DecryptAes256_decrypts_ciphertext()
        {
            Assert.That(
                Parse.DecryptAes256(
                    "TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                    "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                    "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64()),
                Is.EqualTo(Content));
        }

        [Test]
        public void Inflate_decompresses_data()
        {
            Assert.That(
                Parse.Inflate("c8zJUajMLy1SSEosTlVILEpVSErNyc9LVyjJVygtBgA=".Decode64()),
                Is.EqualTo(Content));
        }

        [Test]
        public void ParseEncryptedBlob_parses_kwc3_blob()
        {
            var blob = Salt.Concat("KWC3".ToBytes()).Concat(Content).ToArray();
            var parsed = Parse.ParseEncryptedBlob(blob);

            Assert.That(parsed.Ciphertext, Is.EqualTo(Content));
            Assert.That(parsed.Salt, Is.EqualTo(Salt));
            Assert.That(parsed.Compressed, Is.True);
            Assert.That(parsed.UseDerivedKey, Is.False);
            Assert.That(parsed.Iterations, Is.EqualTo(1));
        }

        [Test]
        public void ParseEncryptedBlob_parses_legacy_blob()
        {
            var blob = Salt.Concat(Content).ToArray();
            var parsed = Parse.ParseEncryptedBlob(blob);

            Assert.That(parsed.Ciphertext, Is.EqualTo(Content));
            Assert.That(parsed.Salt, Is.EqualTo(Salt));
            Assert.That(parsed.Compressed, Is.False);
            Assert.That(parsed.UseDerivedKey, Is.True);
            Assert.That(parsed.Iterations, Is.EqualTo(5));
        }

        [Test]
        public void ParseEncryptedBlob_parses_short_blob_as_legacy()
        {
            var ciphertext = new byte[] {13, 37};
            var blob = Salt.Concat(ciphertext).ToArray();
            var parsed = Parse.ParseEncryptedBlob(blob);

            Assert.That(parsed.Ciphertext, Is.EqualTo(ciphertext));
            Assert.That(parsed.Salt, Is.EqualTo(Salt));
            Assert.That(parsed.Compressed, Is.False);
            Assert.That(parsed.UseDerivedKey, Is.True);
            Assert.That(parsed.Iterations, Is.EqualTo(5));
        }

        [Test]
        [ExpectedException(typeof(ArgumentException), ExpectedMessage = "Blob is too short\r\nParameter name: blob")]
        public void ParseEncryptedBlob_throws_on_too_short_blob()
        {
            Parse.ParseEncryptedBlob(new byte[] {13, 37});
        }

        [Test]
        public void DecryptBlob_returns_decrypted_content_from_kwc3_blob()
        {
            var blob = "c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHRLV0MzxDNg8kGh5rSYkNvXzzn+" +
                       "3xsCKXSKgGhb2pGnbuqQo32blVfJpurp7jj8oSnzxa66";
            Assert.That(Parse.DecryptBlob(blob.Decode64(), Password), Is.EqualTo(Content));
        }

        [Test]
        public void ExtractAccountsFromXml_extracts_accounts_at_different_levels()
        {
            var xml = @"
                <KWAuthentifiant>
                    <KWDataItem key='Id'><![CDATA[1]]></KWDataItem>
                    <KWDataItem key='Title'><![CDATA[dude]]></KWDataItem>
                    <KWDataItem key='Login'><![CDATA[jeffrey.lebowski]]></KWDataItem>
                    <KWDataItem key='Password'><![CDATA[logjammin]]></KWDataItem>
                    <KWDataItem key='Url'><![CDATA[https://dude.com]]></KWDataItem>
                    <KWDataItem key='Note'><![CDATA[Get a new rug!]]></KWDataItem>
                </KWAuthentifiant>
                <KWAuthentifiant>
                    <KWDataItem key='Id'><![CDATA[2]]></KWDataItem>
                    <KWDataItem key='Title'><![CDATA[walter]]></KWDataItem>
                    <KWDataItem key='Login'><![CDATA[walter.sobchak]]></KWDataItem>
                    <KWDataItem key='Password'><![CDATA[worldofpain]]></KWDataItem>
                    <KWDataItem key='Url'><![CDATA[https://nam.com]]></KWDataItem>
                    <KWDataItem key='Note'><![CDATA[Don't roll on Shabbos!]]></KWDataItem>
                </KWAuthentifiant>";

            Assert.That(
                Parse.ExtractAccountsFromXml("<root />"),
                Is.Empty);

            Assert.That(
                Parse.ExtractAccountsFromXml("<root>" + xml + "</root>").Length,
                Is.EqualTo(2));

            Assert.That(
                Parse.ExtractAccountsFromXml("<root><subroot>" + xml + "</subroot></root>").Length,
                Is.EqualTo(2));
        }

        [Test]
        public void ParseAccount_returns_account()
        {
            var e = XDocument.Parse(
                @"<KWAuthentifiant>
                    <KWDataItem key='Id'><![CDATA[1]]></KWDataItem>
                    <KWDataItem key='Title'><![CDATA[dude]]></KWDataItem>
                    <KWDataItem key='Login'><![CDATA[jeffrey.lebowski]]></KWDataItem>
                    <KWDataItem key='Password'><![CDATA[logjammin]]></KWDataItem>
                    <KWDataItem key='Url'><![CDATA[https://dude.com]]></KWDataItem>
                    <KWDataItem key='Note'><![CDATA[Get a new rug!]]></KWDataItem>
                </KWAuthentifiant>");
            var account = Parse.ParseAccount(e.Root);

            Assert.That(account.Id, Is.EqualTo("1"));
            Assert.That(account.Name, Is.EqualTo("dude"));
            Assert.That(account.Username, Is.EqualTo("jeffrey.lebowski"));
            Assert.That(account.Password, Is.EqualTo("logjammin"));
            Assert.That(account.Url, Is.EqualTo("https://dude.com"));
            Assert.That(account.Note, Is.EqualTo("Get a new rug!"));
        }

        [Test]
        public void ParseAccount_returns_account_with_all_defaults()
        {
            var e = XDocument.Parse("<KWAuthentifiant></KWAuthentifiant>");
            var account = Parse.ParseAccount(e.Root);

            Assert.That(account.Id, Is.EqualTo(""));
            Assert.That(account.Name, Is.EqualTo(""));
            Assert.That(account.Username, Is.EqualTo(""));
            Assert.That(account.Password, Is.EqualTo(""));
            Assert.That(account.Url, Is.EqualTo(""));
            Assert.That(account.Note, Is.EqualTo(""));
        }


        [Test]
        public void GetValueForKeyOrDefault_returns_value_when_present()
        {
            var e = XDocument.Parse("<root><KWDataItem key='key'>value</KWDataItem></root>");

            Assert.That(
                Parse.GetValueForKeyOrDefault(e.Root, "key", "default"),
                Is.EqualTo("value"));
        }

        [Test]
        public void GetValueForKeyOrDefault_returns_default_value_when_not_present()
        {
            var e = XDocument.Parse("<root><KWDataItem key='key'>value</KWDataItem></root>");

            Assert.That(
                Parse.GetValueForKeyOrDefault(e.Root, "not-a-key", "default"),
                Is.EqualTo("default"));
        }

        [Test]
        public void ExtractEncryptedAccounts_returns_accounts()
        {
            var blob = "c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHRLV0MzAxW0NQiQrbiEe4yl26Ga" +
                       "gNu1edW/lK/INVrdUkE1+nmpiTZHlNkKKSK5NXbWGuztnk3256De1/2GtaUXjTKOMYvh" +
                       "eV3TJJZWHKHEbSBHJ63OXH/svTCBm1yncDDcqWicVOjQwzP5C4oTmRB9jCAE9A7kx8bZ" +
                       "jz2VQaAAxbKWwCFCSrzFXB22R6DwH+rpnKshrcHiflI8Fy2o000mU1XRhk1yFNqYZkiJ" +
                       "BH0N3aJR7AkqRRALhUaLsMgYWsCxPqD9dP0dsp7A03htUKllVMfjfRexwJfJGi2ezSUv" +
                       "egGVt3k=";

            Assert.That(
                Parse.ExtractEncryptedAccounts(blob.Decode64(), Password).Length,
                Is.EqualTo(2));
        }
    }
}
