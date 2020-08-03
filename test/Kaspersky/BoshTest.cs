// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class BoshTest
    {
        [Fact]
        public void Connect_works()
        {
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
                            $"<jid>{UserJid.Full}</jid>" +
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
                    .ExpectContent("<body ")
                    .ExpectContent("rid='1337'")
                    .ExpectContent("xmlns='http://jabber.org/protocol/httpbind'")
                    .ExpectContent($"to='{UserJid.Host}'")
                    .ExpectContent("xml:lang='en'")
                    .ExpectContent("wait='60'")
                    .ExpectContent("hold='1'")
                    .ExpectContent("content='text/xml; charset=utf-8'")
                    .ExpectContent("ver='1.6'")
                    .ExpectContent("xmpp:version='1.0'")
                    .ExpectContent("xmlns:xmpp='urn:xmpp:xbosh'")
                    .ExpectContent("></body>")
                .Post(response2)
                    .ExpectContent("<body")
                    .ExpectContent("rid='1338'")
                    .ExpectContent("xmlns='http://jabber.org/protocol/httpbind'")
                    .ExpectContent("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>")
                    .ExpectContent("") // TODO: Check auth string is sent
                    .ExpectContent("</auth></body>")
                .Post(response3)
                    .ExpectContent("<body ")
                    .ExpectContent("rid='1339'")
                    .ExpectContent("xmlns='http://jabber.org/protocol/httpbind'")
                    .ExpectContent($"to='{UserJid.Host}'")
                    .ExpectContent("xml:lang='en'")
                    .ExpectContent("xmpp:restart='true'")
                    .ExpectContent("xmlns:xmpp='urn:xmpp:xbosh'")
                    .ExpectContent("></body>")
                .Post(response4)
                    .ExpectContent("<body ")
                    .ExpectContent("rid='1340'")
                    .ExpectContent("xmlns='http://jabber.org/protocol/httpbind'")
                    .ExpectContent("<iq type='set' id='_bind_auth_2' xmlns='jabber:client'>")
                    .ExpectContent("<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>")
                    .ExpectContent($"<resource>{UserJid.Resource}</resource>")
                    .ExpectContent("></bind></iq></body>")
                .Post(response5)
                    .ExpectContent("<body ")
                    .ExpectContent("rid='1341'")
                    .ExpectContent("xmlns='http://jabber.org/protocol/httpbind'")
                    .ExpectContent("<iq type='set' id='_session_auth_2' xmlns='jabber:client'>")
                    .ExpectContent("<session xmlns='urn:ietf:params:xml:ns:xmpp-session'></session>")
                    .ExpectContent("></iq></body>");

            new Bosh("http://bosh.test", UserJid, "password", flow, 1337).Connect();
        }

        [Fact]
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

            var flow = new RestFlow()
                .Post(response);

            var items = new Bosh("http://bosh.test", UserJid, "password", flow)
                .GetChanges("blah", "1337")
                .ToArray();

            Assert.Single(items);
            Assert.Equal("Database", items[0].Type);
            Assert.Equal("AgAAANwFAAA5tWNHwWyUw2VT/XSnzSyx", items[0].Data);
        }

        //
        // Data
        //

        private static readonly Jid UserJid = new Jid("206a9e27-f96a-44d5-ac0d-84efe4f1835a",
                                                      "39.ucp-ntfy.kaspersky-labs.com",
                                                      "portalu3mh3hwy2kp");
    }
}
