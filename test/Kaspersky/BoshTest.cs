// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class BoshTest
    {
        [Fact]
        public void Connect_works()
        {
            var jid = new Jid("206a9e27-f96a-44d5-ac0d-84efe4f1835a",
                              "39.ucp-ntfy.kaspersky-labs.com",
                              "portalu3mh3hwy2kp");

            var response1 =
                "<body wait='60' requests='2' hold='1' from='39.ucp-ntfy.kaspersky-labs.com' accept='deflate,gzip' sid='CR18KyExQ0zE36piRQsC6G954zV7URm0' xmpp:restartlogic='true' xmpp:version='1.0' xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh' xmlns:stream='http://etherx.jabber.org/streams' inactivity='300' maxpause='120'>" +
                    "<stream:features>" +
                        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
                            "<mechanism>PLAIN</mechanism>" +
                        "</mechanisms>" +
                    "</stream:features>" +
                "</body>";
            var response2 =
                "<body sid='O3P2Miv004KukkdFOrOF4tDZMUekR4bt' xmlns='http://jabber.org/protocol/httpbind'>" +
                    "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" +
                "</body>";
            var response3 =
                "<body accept='deflate,gzip' from='39.ucp-ntfy.kaspersky-labs.com' hold='1' inactivity='300' maxpause='120' requests='2' sid='O3P2Miv004KukkdFOrOF4tDZMUekR4bt' wait='60' xmlns='http://jabber.org/protocol/httpbind' xmlns:stream='http://etherx.jabber.org/streams' xmlns:xmpp='urn:xmpp:xbosh' xmpp:restartlogic='true' xmpp:version='1.0'>" +
                    "<stream:features>" +
                        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" +
                        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>" +
                    "</stream:features>" +
                "</body>";
            var response4 =
                "<body sid='O3P2Miv004KukkdFOrOF4tDZMUekR4bt' xmlns='http://jabber.org/protocol/httpbind'>" +
                    "<iq id='_bind_auth_2' type='result'>" +
                        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>" +
                            $"<jid>{jid.Full}</jid>" +
                        "</bind>" +
                    "</iq>" +
                "</body>";
            var response5 =
                "<body sid='O3P2Miv004KukkdFOrOF4tDZMUekR4bt' xmlns='http://jabber.org/protocol/httpbind'>" +
                    "<iq id='_session_auth_2' type='result' xmlns='jabber:client'>" +
                        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>" +
                    "</iq>" +
                "</body>";

            var flow = new RestFlow()
                .Post(response1)
                .Post(response2)
                .Post(response3)
                .Post(response4)
                .Post(response5);

            new Bosh("http://bosh.test").Connect(jid, "password", flow);
        }

        [Fact(Skip = "Need to fake Connect")]
        public void GetChanges_returns_items()
        {
            var response =
                "<body sid='h8EoyOS6Tstt_ltFbLmWwVFitn1cXecC' xmlns='http://jabber.org/protocol/httpbind'>" +
                    "<message from='kpm-sync@39.ucp-ntfy.kaspersky-labs.com' to='206a9e27-f96a-44d5-ac0d-84efe4f1835a#browser#5@39.ucp-ntfy.kaspersky-labs.com/portalwvb4dv0gz5e' id='kpmgetdatabasecommand-browser-5-1595505459433' ctime='2020-07-23T11:57:40Z' type='normal' discard_warn='false' cid='daec98e6-b71b-4de5-9815-72ec23cea5fd' no_offline='true'>" +
                        "<root unique_id='23090566' productVersion='' protocolVersion='' deviceType='0' osType='0' projectVersion='' serverBlob='' MPAuthKeyValueInBase64='' moreChangesAvailable='0' xmlns=''>" +
                            "<changes>" +
                                "<item_0000 unique_id='1203265602' id='2408deddd3cc4519bad9aa33b7e50166' type='Database' dataInBase64='AgAAANwFAAA5tWNHwWyUw2VT/XSnzSyx' />" +
                            "</changes>" +
                        "</root>" +
                        "<body />" +
                    "</message>" +
                "</body>";

            var items = new Bosh("http://bosh.test").GetChanges("blah", 1337);
        }

        [Fact]
        public void DeriveMasterPasswordAuthKey_returns_derived_key()
        {
            var key = Bosh.DeriveMasterPasswordAuthKey(
                "206a9e27-f96a-44d5-ac0d-84efe4f1835a",
                "Password123!",
                new Bosh.DbInfo(2, 1500, "39b56347c16c94c36553fd74a7cd2cb1".DecodeHex()));

            Assert.Equal(
                "d6602e5364ffa30389d9bab817919919ed417aabce1723ebc554099a34375253fee450daa7b0d9959672398c79cde5736d020c73db661f12da6c2ede7c747e2c".DecodeHex(),
                key);
        }

        [Fact]
        public void DeriveEncryptionKey_returns_derived_key()
        {
            var key = Bosh.DeriveEncryptionKey(
                "Password123!",
                new Bosh.DbInfo(2, 1500, "39b56347c16c94c36553fd74a7cd2cb1".DecodeHex()));

            Assert.Equal("d8f2bfe4980d90e3d402844e5332859ecbda531ab24962d2fdad4d39ad98d2f9".DecodeHex(),
                         key);
        }
    }
}
