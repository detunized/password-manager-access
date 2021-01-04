// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class BoshTest
    {
        [Fact]
        public void Ctor_and_GetChanges_connect_to_server_and_return_items()
        {
            var response1 =
                "<?xml version='1.0'?>" +
                "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='14390431958505390437' from='11.ucp-ntfy.kaspersky-labs.com' version='1.0' xml:lang='en'>" +
                    "<stream:features>" +
                        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
                            "<mechanism>PLAIN</mechanism>" +
                        "</mechanisms>" +
                    "</stream:features>";
            var response2 = "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
            var response3 =
                "<?xml version='1.0'?>" +
                "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='14390431958505390437' from='11.ucp-ntfy.kaspersky-labs.com' version='1.0' xml:lang='en'>" +
                    "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>" +
                        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>" +
                    "</stream:features>";
            var response4 =
                "<iq id='_bind_auth_2' type='result'>" +
                    "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>" +
                        $"<jid>{UserJid.Full}</jid>" +
                    "</bind>" +
                "</iq>";
            var response5 =
                "<iq type='result' xmlns='jabber:client' id='_session_auth_2'>" +
                    "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>" +
                "</iq>";
            var response6 =
                "<message from='kpm-sync@11.ucp-ntfy.kaspersky-labs.com' to='543b964d-6259-489e-9603-3495827e0d1b#browser#5@11.ucp-ntfy.kaspersky-labs.com/portaldxy0y5u7qng' id='kpmgetdatabasecommand-browser-5-1608648668840' ctime='2021-01-04T13:35:09Z' type='normal' cid='266e6c8f-aeb1-4245-8878-0a0f23fb6706' no_offline='true'>" +
                    "<root unique_id='23090566' productVersion='' protocolVersion='' deviceType='0' osType='0' projectVersion='' serverBlob='' MPAuthKeyValueInBase64='' moreChangesAvailable='0' xmlns=''>" +
                        "<changes>" +
                            "<item_0000 unique_id='1203265602' id='2408deddd3cc4519bad9aa33b7e50166' type='Database' dataInBase64='AgAAANwFAAA5tWNHwWyUw2VT/XSnzSyx'/>" +
                        "</changes>" +
                    "</root>" +
                    "<body/>" +
                "</message>";


            var flow = new RestFlow()
                .Post(response1)
                    .ExpectContent("<stream:stream")
                    .ExpectContent($"to='{UserJid.Host}'")
                    .ExpectContent("xmlns='jabber:client'")
                    .ExpectContent("xmlns:stream='http://etherx.jabber.org/streams'")
                    .ExpectContent("version='1.0'")
                .Post(response2)
                    .ExpectContent("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>")
                    .ExpectContent("") // TODO: Check auth string is sent
                    .ExpectContent("</auth>")
                .Post(response3)
                    .ExpectContent("<stream:stream")
                    .ExpectContent($"to='{UserJid.Host}'")
                    .ExpectContent("xmlns='jabber:client'")
                    .ExpectContent("xmlns:stream='http://etherx.jabber.org/streams'")
                    .ExpectContent("version='1.0'")
                .Post(response4)
                    .ExpectContent("<iq type='set' id='_bind_auth_2' xmlns='jabber:client'>")
                    .ExpectContent("<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>")
                    .ExpectContent($"<resource>{UserJid.Resource}</resource>")
                    .ExpectContent("></bind></iq>")
                .Post(response5)
                    .ExpectContent("<iq type='set' id='_session_auth_2' xmlns='jabber:client'>")
                    .ExpectContent("<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>")
                    .ExpectContent("></iq>")
                .Post(response6)
                    .ExpectContent("<message ")
                    .ExpectContent("xmlns='jabber:client'")
                    .ExpectContent("id='command-name-browser-5-")
                    .ExpectContent($"to='kpm-sync@{UserJid.Host}'")
                    .ExpectContent($"from='{UserJid.Bare}'")
                    .ExpectContent("<root unique_id='4213' productVersion='' protocolVersion='' projectVersion='9.2.0.1' deviceType='0' osType='0' />")
                    .ExpectContent("></message>");

            var items = new Bosh("http://bosh.test", UserJid, "password", new RestBoshTransport(flow))
                .GetChanges("command-name", "4213")
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

    internal class RestBoshTransport: IBoshTransport
    {
        public RestBoshTransport(IRestTransport transport)
        {
            _rest = new RestClient(transport);
        }

        //
        // IBoshTransport
        //

        public Exception? Connect(string url)
        {
            _url = url;
            return null;
        }

        public Try<string> Request(string body, int expectedMessageCount)
        {
            var response = _rest.PostRaw(_url, body);
            if (response.IsSuccessful)
                return Try.FromValue(response.Content);

            return response.HasError
                ? Try<string>.FromError(response.Error)
                : Try<string>.FromError($"Request to '{_url}' failed with HTTP status {(int)response.StatusCode}");
        }

        //
        // IDisposable
        //

        public void Dispose()
        {
            // Nothing to dispose of
        }

        private readonly RestClient _rest;
        private string _url = "";
    }
}
