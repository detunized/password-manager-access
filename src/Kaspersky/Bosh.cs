// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
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

        public void Connect(string jid, string password, IRestTransport transport)
        {
            _jid = Jid.Parse(jid);
            _password = password;
            _requestId = new Random().Next(); // TODO: Remove randomness in tests
            _rest = new RestClient(transport);

            const string bosh = "urn:xmpp:xbosh";
            const string sasl = "urn:ietf:params:xml:ns:xmpp-sasl";
            const string client = "jabber:client";
            const string bind = "urn:ietf:params:xml:ns:xmpp-bind";

            //
            // 1
            //

            var body = BuildBody();
            body.Add(new XAttribute("to", _jid.Domain));
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
            body.Add(new XAttribute("to", _jid.Domain));
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
            if (xJid == null || xJid.Value != _jid.Original)
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

            // Auth finished

            //
            // Get DB
            //

            bt = BuildBodyTemplate();
            bt.Replace("$", "<message xmlns='jabber:client' id='kpmgetdatabasecommand-browser-5-1595431464704' " +
                            $"to='kpm-sync@{_jid.Domain}' from='{_jid.Bare}'>$</message>");
            bt.Replace("$", "<body />" +
                            "<root unique_id='1830647823' productVersion='' protocolVersion='' " +
                            "projectVersion='9.2.0.1' deviceType='0' osType='0' />");

            response = Request(bt.ToString());
            var changes = GetChild(response, "body/message/root/changes");
            if (changes == null)
                throw MakeError("Failed to retrieve the database info");

            var dbInfoItem = changes.Elements().FirstOrDefault(x => x.Attribute("type")?.Value == "Database");
            if (dbInfoItem == null)
                throw MakeError("Database info is not found in the response");

            var dbInfoBlob = dbInfoItem.Attribute("dataInBase64")?.Value.Decode64();
            var dbInfo = DbInfo.Parse(dbInfoBlob);
        }

        //
        // Internal
        //

        // jid: user@domain/resource
        internal readonly struct Jid
        {
            public readonly string Username;
            public readonly string Domain;
            public readonly string Resource;
            public readonly string Original;

            public string Bare => $"{Username}@{Domain}";

            public static Jid Parse(string jid)
            {
                var at = jid.IndexOf('@');
                var slash = jid.IndexOf('/');
                if (at < 0 || slash < 0)
                    throw new InternalErrorException($"Invalid JID '{jid}'");

                return new Jid(username: jid.Substring(0, at),
                               domain: jid.Substring(at + 1, slash - at - 1),
                               resource: jid.Substring(slash + 1),
                               original: jid);
            }

            internal Jid(string username, string domain, string resource, string original): this()
            {
                Username = username;
                Domain = domain;
                Resource = resource;
                Original = original;
            }
        }

        internal readonly struct DbInfo
        {
            public readonly int Version;
            public readonly int Iterations;
            public readonly byte[] Salt;

            public static DbInfo Parse(byte[] blob)
            {
                return blob.Open(r =>
                {
                    var version = r.ReadInt32();
                    var iterations = r.ReadInt32();
                    var salt = r.ReadBytes(16);

                    return new DbInfo(version, iterations, salt);
                });
            }

            internal DbInfo(int version, int iterations, byte[] salt)
            {
                Version = version;
                Iterations = iterations;
                Salt = salt;
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
            return $"{jid.Username}@{jid.Domain}\0{jid.Username}\0{password}".ToBase64();
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

        internal static void RemoveNamespaces(XElement e)
        {
            if (e == null)
                return;

            e.Name = XName.Get(e.Name.LocalName);

            foreach (var child in e.Elements())
                RemoveNamespaces(child);
        }

        internal static byte[] DeriveMasterPasswordAuthKey(string userId, string password, DbInfo dbInfo)
        {
            return Pbkdf2.GenerateSha256(password: DeriveEncryptionKey(password, dbInfo),
                                         salt: Encoding.Unicode.GetBytes(userId),
                                         iterationCount: 1500,
                                         byteCount: 64);
        }

        internal static byte[] DeriveEncryptionKey(string password, DbInfo dbInfo)
        {
            return Crypto.Pbkdf2Sha256(password: password,
                                       salt: dbInfo.Salt,
                                       iterations: dbInfo.Iterations,
                                       byteCount: 32);
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
