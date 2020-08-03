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
        private readonly Jid _jid;
        private readonly string _password;
        private readonly RestClient _rest;
        private int _requestId;
        private string _sessionId;

        public Bosh(string url, Jid jid, string password, IRestTransport transport):
            this(url, jid, password, transport, new Random().Next())
        {
        }

        public void Connect()
        {
            //
            // 1. Initialize
            //

            var rt = GenerateNextRequestTemplate();
            rt.AddAttribute($"to='{_jid.Host}'");
            rt.AddAttribute("wait='60'");
            rt.AddAttribute("hold='1'");
            rt.AddAttribute("ver='1.6'");
            rt.AddAttribute("content='text/xml; charset=utf-8'");
            rt.AddAttribute("xml:lang='en'");
            rt.AddAttribute("xmpp:version='1.0'");
            rt.AddAttribute("xmlns:xmpp='urn:xmpp:xbosh'");

            var response = Request(rt.Bake());
            if (response.Root.Attribute("sid") is { } sid)
                _sessionId = sid.Value;

            var hasPlain = response.XPathSelectElements("//*[local-name() = 'mechanism']")
                .Any(x => x.Value == "PLAIN");
            if (!hasPlain)
                throw MakeError("PLAIN auth method is not supported by the server");

            //
            // 2. Authenticate
            //

            var auth = GetPlainAuthString(_jid, _password);
            rt = GenerateNextRequestTemplate();
            rt.AddTag($"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth}", "</auth>");

            response = Request(rt.Bake());
            if (GetChild(response, "body/success") == null)
                throw MakeError("Authentication failed");

            //
            // 3. Restart
            //

            rt = GenerateNextRequestTemplate();
            rt.AddAttribute($"to='{_jid.Host}'");
            rt.AddAttribute("xml:lang='en'");
            rt.AddAttribute("xmpp:restart='true'");
            rt.AddAttribute("xmlns:xmpp='urn:xmpp:xbosh'");

            response = Request(rt.Bake());
            if (GetChild(response, "body/features/bind") == null ||
                GetChild(response, "body/features/session") == null)
                throw MakeError("Restart failed");

            //
            // 4. Bind resource
            //

            rt = GenerateNextRequestTemplate();
            rt.AddTag("<iq type='set' id='_bind_auth_2' xmlns='jabber:client'>", "</iq>");
            rt.AddTag("<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>", "</bind>");
            rt.AddTag($"<resource>{_jid.Resource}", "</resource>");

            response = Request(rt.Bake());
            var xJid = GetChild(response, "body/iq/bind/jid");
            if (xJid == null || xJid.Value != _jid.Full)
                throw MakeError("Resource bind failed");

            //
            // 5. Set session
            //

            rt = GenerateNextRequestTemplate();
            rt.AddTag("<iq type='set' id='_session_auth_2' xmlns='jabber:client'>", "</iq>");
            rt.AddTag("<session xmlns='urn:ietf:params:xml:ns:xmpp-session'>", "</session>");

            response = Request(rt.Bake());
            if (GetChild(response, "body/iq/session") == null)
                throw MakeError("Session auth failed");
        }

        public IEnumerable<Change> GetChanges(string command, string commandId, string authKey = "")
        {
            var body = GenerateNextBodyTemplate();

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

        internal class RequestTemplate
        {
            private StringBuilder _draft;
            private string _baked = null;

            private const string Ap = "$a$";
            private const string Tp = "$t$";

            public RequestTemplate(int requestId, string sessionId = null)
            {
                _draft = new StringBuilder(1024);

                _draft.Append($"<body rid='{requestId}' xmlns='http://jabber.org/protocol/httpbind'");
                if (sessionId != null)
                    _draft.Append($" sid='{sessionId}'");
                _draft.Append($"{Ap}>{Tp}</body>");
            }

            public void AddAttribute(string attribute)
            {
                VerifyStillRaw();
                _draft.Replace(Ap, $" {attribute}{Ap}");
            }

            public void AddTag(string open, string close)
            {
                VerifyStillRaw();
                _draft.Replace(Tp, $"{open}{Tp}{close}");
            }

            public string Bake()
            {
                if (_baked == null)
                {
                    _draft.Replace(Ap, "");
                    _draft.Replace(Tp, "");
                    _baked = _draft.ToString();
                }

                return _baked;
            }

            private void VerifyStillRaw()
            {
                if (_baked != null)
                    throw new InternalErrorException("Cannot modify an already baked template");
            }
        }

        // TODO: Rename this to EncryptedItem
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

        // For testing only
        internal Bosh(string url, Jid jid, string password, IRestTransport transport, int requestId)
        {
            _url = url;
            _jid = jid;
            _password = password;
            _rest = new RestClient(transport);
            _requestId = requestId;
        }

        internal RequestTemplate GenerateNextRequestTemplate()
        {
            return new RequestTemplate(_requestId++, _sessionId);
        }

        internal StringBuilder GenerateNextBodyTemplate()
        {
            var sb = new StringBuilder(4096);
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

        internal XDocument Request(string body)
        {
            var response = _rest.PostRaw(_url, body);
            if (!response.IsSuccessful)
                throw MakeError(response);

            // TODO: Do we need this?
            // Remove all namespaces from all the elements. Otherwise it's a giant PITA to deal
            // with the namespaced names, XPath fails all the time and stuff like that.
            //RemoveNamespaces(xml.Root);

            return XDocument.Parse(response.Content);
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
