// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using System.Xml.XPath;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal class Bosh
    {
        private readonly string _url;
        private Jid _jid;
        private string _password;
        private int _requestId;
        private RestClient _rest;
        private string _sessionId;

        public Bosh(string url)
        {
            _url = url;
        }

        public void Connect(Jid jid, string password, IRestTransport transport)
        {
            _jid = jid;
            _password = password;
            _requestId = new Random().Next(); // TODO: Remove randomness in tests
            _rest = new RestClient(transport);

            const string bosh = "urn:xmpp:xbosh";
            const string sasl = "urn:ietf:params:xml:ns:xmpp-sasl";
            //const string client = "jabber:client";
            //const string bind = "urn:ietf:params:xml:ns:xmpp-bind";

            //
            // 1
            //

            var body = BuildBody();
            body.Add(new XAttribute("to", _jid.Host));
            body.Add(new XAttribute("wait", 60));
            body.Add(new XAttribute("hold", 1));
            body.Add(new XAttribute("ver", "1.6"));
            body.Add(new XAttribute("content", "text/xml; charset=utf-8"));
            body.Add(new XAttribute(XNamespace.Xml + "lang", "en"));
            body.Add(new XAttribute(XNamespace.Xmlns + "xmpp", bosh));
            body.Add(new XAttribute(XNamespace.Get(bosh) + "version", "1.0"));

            var response = Request(body);
            if (response.Root.Attribute("sid") is { } sid)
                _sessionId = sid.Value;

            var hasPlain = response.XPathSelectElements("//*[local-name() = 'mechanism']")
                .Any(x => x.Value == "PLAIN");
            if (!hasPlain)
                throw MakeError("PLAIN auth method is not supported by the server");

            //
            // 2
            //

            body = BuildBody();
            body.Add(new XElement(XNamespace.Get(sasl) + "auth",
                                  new XAttribute("mechanism", "PLAIN"),
                                  new XText(GetPlainAuthString(_jid, _password))));

            response = Request(body);
            if (GetChild(response, "body/success") == null)
                throw MakeError("Authentication failed");

            //
            // 3
            //

            body = BuildBody();
            body.Add(new XAttribute("to", _jid.Host));
            body.Add(new XAttribute(XNamespace.Xml + "lang", "en"));
            body.Add(new XAttribute(XNamespace.Xmlns + "xmpp", bosh));
            body.Add(new XAttribute(XNamespace.Get(bosh) + "restart", "true"));

            response = Request(body);
            if (GetChild(response, "body/features/bind") == null ||
                GetChild(response, "body/features/session") == null)
                throw MakeError("Restart failed");

            //
            // 4
            //

            var bt = BuildBodyTemplate();
            bt.Replace("$", "<iq type='set' id='_bind_auth_2' xmlns='jabber:client'>$</iq>");
            bt.Replace("$", "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>$</bind>");
            bt.Replace("$", $"<resource>{_jid.Resource}</resource>");

            response = Request(bt.ToString());
            var xJid = GetChild(response, "body/iq/bind/jid");
            if (xJid == null || xJid.Value != _jid.Full)
                throw MakeError("Resource bind failed");

            //
            // 5
            //

            bt = BuildBodyTemplate();
            bt.Replace("$", "<iq id='_session_auth_2' type='set' xmlns='jabber:client'>$</id>");
            bt.Replace("$", "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>");

            response = Request(bt.ToString());
            if (GetChild(response, "body/iq/session") == null)
                throw MakeError("Session auth failed");
        }

        public IEnumerable<Change> GetChanges(string command, string commandId, string authKey = "")
        {
            var body = BuildBodyTemplate();

            var timestamp = Os.UnixMilliseconds();
            var id = $"{command}-{Client.DeviceKind}-{Client.ServiceId}-{timestamp}";
            body.Replace(
                "$",
                $"<message xmlns='jabber:client' id='{id}' to='kpm-sync@{_jid.Host}' from='{_jid.Bare}'>" +
                    $"<root unique_id='{commandId}' productVersion='' protocolVersion='' projectVersion='9.2.0.1' deviceType='0' osType='0' MPAuthKeyValueInBase64='{authKey}'/>" +
                    "<body />" +
                "</message>");

            var response = Request(body.ToString());
            var changes = GetChild(response, "body/message/root/changes");
            if (changes == null)
                throw MakeError($"Failed to retrieve changes via {command}");

            return
                from e in changes.Elements()
                let type = e.Attribute("type")?.Value
                where type != null
                select new Change(type, e.Attribute("dataInBase64")?.Value ?? "");
        }

        //
        // Internal
        //

        internal readonly struct Change
        {
            public readonly string Type;
            public readonly string Data;

            public Change(string type, string data)
            {
                Type = type;
                Data = data;
            }
        }

        internal XElement BuildBody()
        {
            var xmlns = XNamespace.Get("http://jabber.org/protocol/httpbind");
            var body = new XElement(xmlns + "body", new XAttribute("rid", _requestId++));
            if (_sessionId != null)
                body.Add(new XAttribute("sid", _sessionId));

            return body;
        }

        internal StringBuilder BuildBodyTemplate()
        {
            var sb = new StringBuilder();
            sb.AppendFormat("<body rid='{0}' xmlns='http://jabber.org/protocol/httpbind'", _requestId++);
            if (_sessionId != null)
                sb.AppendFormat(" sid='{0}'", _sessionId);
            sb.Append(">$</body>");
            return sb;
        }

        internal static string GetPlainAuthString(Jid jid, string password)
        {
            return $"{jid.Bare}\0{jid.Node}\0{password}".ToBase64();
        }

        internal XDocument Request(XElement body)
        {
            return Request(body.ToString());
        }

        internal XDocument Request(string body)
        {
            Console.WriteLine($">>>: {body}");
            var response = _rest.PostRaw(_url, body);
            if (!response.IsSuccessful)
                throw MakeError(response);

            Console.WriteLine($"<<<: {response.Content}");
            var xml = XDocument.Parse(response.Content);

            // Remove all namespaces from all the elements. Otherwise it's a giant PITA to deal
            // with the namespaced names, XPath fails all the time and stuff like that.
            //RemoveNamespaces(xml.Root);

            return xml;
        }

        internal static XElement GetChild(XContainer root, string path, XElement defaultValue = null)
        {
            var current = root;
            foreach (var name in path.Split('/'))
            {
                current = current.Elements().FirstOrDefault(x => x.Name.LocalName == name);
                if (current == null)
                    return defaultValue;
            }

            return (XElement)current;
        }

        private static BaseException MakeError(RestResponse<string> response)
        {
            throw new InternalErrorException($"Request to {response.RequestUri} failed");
        }

        private static BaseException MakeError(string message)
        {
            throw new InternalErrorException(message);
        }
    }
}
