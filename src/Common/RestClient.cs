// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

// TODO: Should this file be split?
namespace PasswordManagerAccess.Common
{
    using HttpCookies = Dictionary<string, string>;
    using HttpHeaders = Dictionary<string, string>;
    using PostParameters = Dictionary<string, object>;
    using ReadOnlyHttpCookies = IReadOnlyDictionary<string, string>;
    using ReadOnlyHttpHeaders = IReadOnlyDictionary<string, string>;
    using SendAsyncType = Func<HttpRequestMessage, Task<HttpResponseMessage>>;

    // Generic response
    internal class RestResponse
    {
        public HttpStatusCode StatusCode { get; internal set; }
        public HttpHeaders Headers { get; internal set; }
        public Exception Error { get; internal set; }
        public Dictionary<string, string> Cookies { get; internal set; }
        public Uri RequestUri { get; internal set; }

        // On HTTP 2xx and no exceptions
        public virtual bool IsSuccessful => IsHttpOk && !HasError;

        // On HTTP 2xx
        public bool IsHttpOk => (int)StatusCode / 100 == 2;

        // On HTTP other than 2xx, but not other exceptions
        public bool IsHttpError => !IsHttpOk && !HasError;

        // On other error
        public bool HasError => Error != null;

        public bool IsNetworkError => HasError && Error is HttpRequestException;
    }

    // Adds original content received on top of the response
    // TContent could be string (text) or byte[] (binary)
    internal class RestResponse<TContent> : RestResponse
    {
        public TContent Content { get; internal set; }
    }

    // Adds deserialized data on top of the content
    internal class RestResponse<TContent, TData> : RestResponse<TContent>
    {
        public TData Data { get; internal set; }

        // Also check if the de-serialization went through
        public override bool IsSuccessful => base.IsSuccessful && Data != null;
    }

    //
    // RestMessageHandler
    //

    internal class RestMessageHandler : HttpMessageHandler
    {
        public RestMessageHandler(SendAsyncType sendAsync)
        {
            _sendAsync = sendAsync;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _sendAsync(request);
        }

        private readonly SendAsyncType _sendAsync;
    }

    //
    // IRestTransport
    //

    // TODO: Maybe the transport should not handle the redirects
    internal interface IRestTransport : IDisposable
    {
        void MakeRequest<TContent>(
            Uri uri,
            HttpMethod method,
            HttpContent content,
            ReadOnlyHttpHeaders headers,
            ReadOnlyHttpCookies cookies,
            int maxRedirectCount,
            RestResponse<TContent> allocatedResult
        );

        Task MakeRequestAsync<TContent>(
            Uri uri,
            HttpMethod method,
            HttpContent content,
            ReadOnlyHttpHeaders headers,
            ReadOnlyHttpCookies cookies,
            int maxRedirectCount,
            RestResponse<TContent> allocatedResult,
            CancellationToken cancellationToken
        );
    }

    //
    // RestTransport
    //

    internal class RestTransport : IRestTransport
    {
        public RestTransport()
            : this(MakeDefaultHttpClient()) { }

        public RestTransport(SendAsyncType sendAsync)
            : this(MakeHttpClient(sendAsync)) { }

        public void MakeRequest<TContent>(
            Uri uri,
            HttpMethod method,
            HttpContent content,
            ReadOnlyHttpHeaders headers,
            ReadOnlyHttpCookies cookies,
            int maxRedirectCount,
            RestResponse<TContent> allocatedResult
        )
        {
            allocatedResult.RequestUri = uri;

            try
            {
                // TODO: Dispose this
                var request = new HttpRequestMessage(method, uri) { Content = content };

                // Set headers
                foreach (var h in headers)
                    request.Headers.TryAddWithoutValidation(h.Key, h.Value);

                // Set cookies
                if (cookies.Count > 0)
                {
                    var cookieHeaderValue = string.Join("; ", cookies.Select(x => $"{x.Key}={x.Value}"));
                    request.Headers.TryAddWithoutValidation("Cookie", cookieHeaderValue);
                }

                // Don't use .Result here but rather .GetAwaiter().GetResult()
                // It produces a nicer call stack and no AggregateException nonsense
                // https://stackoverflow.com/a/36427080/362938
                // TODO: Dispose this?
                var response = _http.SendAsync(request).GetAwaiter().GetResult();

                var responseCookies = ParseResponseCookies(response, uri);
                var allCookies = cookies.MergeCopy(responseCookies);

                // Redirect if still possible (HTTP Status 3XX)
                if ((int)response.StatusCode / 100 == 3 && maxRedirectCount > 0)
                {
                    // Uri ctor should take care of both absolute and relative redirects. There have
                    // been problems with Android in the past.
                    // (see https://github.com/detunized/password-manager-access/issues/21)
                    var newUri = new Uri(uri, response.Headers.Location);

                    // Redirect always does a GET with no content
                    MakeRequest(newUri, HttpMethod.Get, null, headers, allCookies, maxRedirectCount - 1, allocatedResult);
                    return;
                }

                // Set up the result
                allocatedResult.StatusCode = response.StatusCode;
                allocatedResult.Cookies = allCookies;

                switch (allocatedResult)
                {
                    case RestResponse<string> text:
                        text.Content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        break;
                    case RestResponse<byte[]> binary:
                        binary.Content = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                        break;
                    default:
                        throw new InternalErrorException($"Unsupported content type {typeof(TContent)}");
                }

                // TODO: Here we're ignoring possible duplicated headers. See if we need to preserve those!
                allocatedResult.Headers = response.Headers.ToDictionary(x => x.Key, x => x.Value.FirstOrDefault() ?? "");
            }
            catch (HttpRequestException e)
            {
                allocatedResult.Error = e;
            }
        }

        // TODO: Refactor to share the code with the non-async version
        public async Task MakeRequestAsync<TContent>(
            Uri uri,
            HttpMethod method,
            HttpContent content,
            ReadOnlyHttpHeaders headers,
            ReadOnlyHttpCookies cookies,
            int maxRedirectCount,
            RestResponse<TContent> allocatedResult,
            CancellationToken cancellationToken
        )
        {
            allocatedResult.RequestUri = uri;

            try
            {
                // TODO: Dispose this
                var request = new HttpRequestMessage(method, uri) { Content = content };

                // Set headers
                foreach (var h in headers)
                    request.Headers.TryAddWithoutValidation(h.Key, h.Value);

                // Set cookies
                if (cookies.Count > 0)
                {
                    var cookieHeaderValue = string.Join("; ", cookies.Select(x => $"{x.Key}={x.Value}"));
                    request.Headers.TryAddWithoutValidation("Cookie", cookieHeaderValue);
                }

                // Don't use .Result here but rather .GetAwaiter().GetResult()
                // It produces a nicer call stack and no AggregateException nonsense
                // https://stackoverflow.com/a/36427080/362938
                // TODO: Dispose this?
                var response = _http.SendAsync(request).GetAwaiter().GetResult();

                var responseCookies = ParseResponseCookies(response, uri);
                var allCookies = cookies.MergeCopy(responseCookies);

                // Redirect if still possible (HTTP Status 3XX)
                if ((int)response.StatusCode / 100 == 3 && maxRedirectCount > 0)
                {
                    // Uri ctor should take care of both absolute and relative redirects. There have
                    // been problems with Android in the past.
                    // (see https://github.com/detunized/password-manager-access/issues/21)
                    var newUri = new Uri(uri, response.Headers.Location);

                    // Redirect always does a GET with no content
                    MakeRequest(newUri, HttpMethod.Get, null, headers, allCookies, maxRedirectCount - 1, allocatedResult);
                    return;
                }

                // Set up the result
                allocatedResult.StatusCode = response.StatusCode;
                allocatedResult.Cookies = allCookies;

                switch (allocatedResult)
                {
                    case RestResponse<string> text:
                        text.Content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        break;
                    case RestResponse<byte[]> binary:
                        binary.Content = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        break;
                    default:
                        throw new InternalErrorException($"Unsupported content type {typeof(TContent)}");
                }

                // TODO: Here we're ignoring possible duplicated headers. See if we need to preserve those!
                allocatedResult.Headers = response.Headers.ToDictionary(x => x.Key, x => x.Value.FirstOrDefault() ?? "");
            }
            catch (HttpRequestException e)
            {
                allocatedResult.Error = e;
            }
        }

        //
        // Private
        //

        private static HttpCookies ParseResponseCookies(HttpResponseMessage response, Uri uri)
        {
            // Parse cookies
            var jar = new CookieContainer();
            if (response.Headers.Contains(SetCookieHeader))
            {
                foreach (var h in response.Headers.GetValues(SetCookieHeader))
                {
                    try
                    {
                        jar.SetCookies(uri, h);
                    }
                    catch (CookieException)
                    {
                        // Sometimes the domain on a cookie is invalid. CookieContainer doesn't like that.
                        // Just ignore those cookies.
                    }
                }
            }

            // Extract cookies
            return jar.GetCookies(uri).Cast<Cookie>().ToDictionary(x => x.Name, x => x.Value);
        }

        private static bool IsBinaryResponse(HttpResponseMessage response)
        {
            // When "Content-Type" is present and is set to "application/octet-stream" it's binary
            return response.Content.Headers.TryGetValues("Content-Type", out var contentType) && contentType.Contains("application/octet-stream");
        }

        private RestTransport(HttpClient http)
        {
            _http = http;
        }

        private static HttpClient MakeDefaultHttpClient()
        {
            var handler = new HttpClientHandler
            {
                UseCookies = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.All,
            };

            // On iOS .NET 8 which the native HTTP handler behaves differently than on desktop .NET.
            // We need to enable cookies explicitly, otherwise the Set-Cookie headers are discarded
            // from the response headers.
            // TODO: This potentially has some negative side effects that we need to investigate!
            if (OperatingSystem.IsIOS())
            {
                handler.UseCookies = true;
            }
            else if (!OperatingSystem.IsAndroid())
            {
                // Mobile .NET 8 doesn't support proxies yet
                // To use on the iOS Simulator just use the macOS proxy in Charles
                // To use on Android add a proxy to the Wi-Fi settings and install the certificate from Charles
#if MITM_PROXY
                handler.Proxy = new WebProxy("http://127.0.0.1:8888");
#endif
            }

            return new HttpClient(handler, true);
        }

        private static HttpClient MakeHttpClient(SendAsyncType sendAsync)
        {
            return new HttpClient(new RestMessageHandler(sendAsync), true);
        }

        //
        // Data
        //

        private const string SetCookieHeader = "Set-Cookie";

        private readonly HttpClient _http;

        //
        // IDisposable
        //

        public void Dispose()
        {
            Dispose(true);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _http.Dispose();
                }

                _disposed = true;
            }
        }

        private bool _disposed;
    }

    //
    // IRequestSigner
    //

    // Signs the request by returning a new set of headers
    internal interface IRequestSigner
    {
        ReadOnlyHttpCookies Sign(Uri uri, HttpMethod method, ReadOnlyHttpCookies headers, HttpContent content);
    }

    // Unit request signer that does nothing
    internal class UnitRequestSigner : IRequestSigner
    {
        public ReadOnlyHttpCookies Sign(Uri uri, HttpMethod method, ReadOnlyHttpCookies headers, HttpContent content)
        {
            return headers;
        }
    }

    //
    // RestClient
    //

    // This class is no longer immutable. It's now possible to mutate the default headers and cookies.
    // This class is not trying to manage the transport lifetime. It's managed externally. So it's possible to create multiple
    // RestClients with the same transport, the copies are cheap.
    internal partial class RestClient
    {
        // TODO: Make these readonly dictionaries
        public static readonly HttpHeaders NoHeaders = new();
        public static readonly HttpCookies NoCookies = new();

        // NoParameters is a normal value, it's just for convenience to not type
        // new Dictionary<string, object>() every time. Plus it saves an allocation.
        // For the JSON requests it's sent as "{}", for the Form requests as "".
        public static readonly PostParameters NoParameters = new();

        // JsonBlank is a special case. It's used to send blank or no content which is
        // impossible to express in JSON. This is only relevant for JSON variants.
        public static readonly PostParameters JsonBlank = new();

        // JsonNull is used to send "null". This is only relevant for JSON variants.
        public static readonly PostParameters JsonNull = new();

        // TODO: Convert to properties
        public readonly IRestTransport Transport;
        public readonly string BaseUrl;
        public IRequestSigner Signer { get; private set; }
        public ReadOnlyHttpHeaders DefaultHeaders => _defaultHeaders;
        public ReadOnlyHttpCookies DefaultCookies => _defaultCookies;
        public readonly ISimpleLogger Logger;
        public readonly bool UseSystemJson;

        // Mutable state behind r/o properties
        private readonly Dictionary<string, string> _defaultHeaders;
        private readonly Dictionary<string, string> _defaultCookies;

        public RestClient(
            IRestTransport transport,
            string baseUrl = "",
            IRequestSigner signer = null,
            ReadOnlyHttpHeaders defaultHeaders = null,
            ReadOnlyHttpHeaders defaultCookies = null,
            ISimpleLogger logger = null,
            bool useSystemJson = false
        )
        {
            Transport = transport;
            BaseUrl = baseUrl;
            Signer = signer ?? new UnitRequestSigner();
            Logger = logger;
            UseSystemJson = useSystemJson;

            // We need a copy to make sure the caller doesn't mutate the original headers
            _defaultHeaders = defaultHeaders?.Count > 0 ? new Dictionary<string, string>(defaultHeaders) : [];
            _defaultCookies = defaultCookies?.Count > 0 ? new Dictionary<string, string>(defaultCookies) : [];
        }

        //
        // Mutate state
        //

        public void AddOrUpdateHeader(string name, string value) => _defaultHeaders[name] = value;

        public bool RemoveHeader(string name) => _defaultHeaders.Remove(name);

        public void AddOrUpdateCookie(string name, string value) => _defaultCookies[name] = value;

        public bool RemoveCookie(string name) => _defaultCookies.Remove(name);

        // Pass null to remove the signer
        public void SetSigner(IRequestSigner signer)
        {
            Signer = signer ?? new UnitRequestSigner();
        }

        //
        // GET
        //

        public RestResponse<string> Get(string endpoint, HttpHeaders headers = null, HttpCookies cookies = null, int maxRedirects = MaxRedirects)
        {
            return MakeRequest<string>(endpoint, HttpMethod.Get, null, headers ?? NoHeaders, cookies ?? NoCookies, maxRedirects);
        }

        public RestResponse<byte[]> GetBinary(
            string endpoint,
            HttpHeaders headers = null,
            HttpCookies cookies = null,
            int maxRedirects = MaxRedirects
        )
        {
            return MakeRequest<byte[]>(endpoint, HttpMethod.Get, null, headers ?? NoHeaders, cookies ?? NoCookies, maxRedirects);
        }

        public RestResponse<string, T> Get<T>(
            string endpoint,
            HttpHeaders headers = null,
            HttpCookies cookies = null,
            int maxRedirects = MaxRedirects
        )
        {
            return MakeRequest<string, T>(
                endpoint,
                HttpMethod.Get,
                null,
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                maxRedirects,
                DeserializeFromJson<T>
            );
        }

        //
        // POST JSON
        //

        public RestResponse<string> PostJson(string endpoint, PostParameters parameters, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string>(
                endpoint,
                HttpMethod.Post,
                ToJsonContent(parameters),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects
            );
        }

        public RestResponse<string, T> PostJson<T>(string endpoint, PostParameters parameters, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string, T>(
                endpoint,
                HttpMethod.Post,
                ToJsonContent(parameters),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                DeserializeFromJson<T>
            );
        }

        //
        // POST form
        //

        public RestResponse<string> PostForm(string endpoint, PostParameters parameters, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string>(
                endpoint,
                HttpMethod.Post,
                ToFormContent(parameters),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects
            );
        }

        public RestResponse<string, T> PostForm<T>(string endpoint, PostParameters parameters, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string, T>(
                endpoint,
                HttpMethod.Post,
                ToFormContent(parameters),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                DeserializeFromJson<T>
            );
        }

        //
        // POST raw
        //

        public RestResponse<string> PostRaw(string endpoint, string content, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string>(
                endpoint,
                HttpMethod.Post,
                new StringContent(content),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects
            );
        }

        //
        // PUT
        //

        public RestResponse<string> Put(string endpoint, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string>(endpoint, HttpMethod.Put, null, headers ?? NoHeaders, cookies ?? NoCookies, MaxRedirects);
        }

        public RestResponse<string, T> Put<T>(string endpoint, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string, T>(
                endpoint,
                HttpMethod.Put,
                null,
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                DeserializeFromJson<T>
            );
        }

        //
        // PUT JSON
        //

        public RestResponse<string> PutJson(string endpoint, PostParameters parameters, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string>(endpoint, HttpMethod.Put, ToJsonContent(parameters), headers ?? NoHeaders, cookies ?? NoCookies, MaxRedirects);
        }

        public RestResponse<string, T> PutJson<T>(string endpoint, PostParameters parameters, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<string, T>(
                endpoint,
                HttpMethod.Put,
                ToJsonContent(parameters),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                DeserializeFromJson<T>
            );
        }

        //
        // Internal
        //

        internal Uri MakeAbsoluteUri(string endpoint)
        {
            // It's allowed to have no base URL and then the endpoint is an absolute URL
            // The Uri constructor should take care of broken URL formats and throw.
            // TODO: Should we throw our own exceptions instead?
            if (BaseUrl.IsNullOrEmpty())
                return new Uri(endpoint);

            if (endpoint.IsNullOrEmpty())
                return new Uri(BaseUrl);

            // In general the strings are corrected to be joined with one slash in between them.
            // One exception is the endpoints starting with a question mark.

            // There's one special case here: when joining 'http://domain.tld' and '?endpoint'
            // there should be no slash inserted, but the Uri constructor inserts one anyway.
            // So we account for this special behavior in the tests.

            var url = (BaseUrl.Last(), endpoint[0]) switch
            {
                ('/', '/') => BaseUrl + endpoint.Substring(1),
                (_, '/') => BaseUrl + endpoint,
                ('/', _) => BaseUrl + endpoint,
                (_, '?') => BaseUrl + endpoint,
                (_, _) => BaseUrl + '/' + endpoint,
            };

            return new Uri(url);
        }

        //
        // Private
        //

        private RestResponse<TContent> MakeRequest<TContent>(
            string endpoint,
            HttpMethod method,
            HttpContent content,
            HttpHeaders headers,
            HttpCookies cookies,
            int maxRedirects
        )
        {
            return MakeRequest<RestResponse<TContent>, TContent>(
                endpoint,
                method,
                content,
                headers,
                cookies,
                maxRedirects,
                new RestResponse<TContent>()
            );
        }

        private RestResponse<TContent, TData> MakeRequest<TContent, TData>(
            string endpoint,
            HttpMethod method,
            HttpContent content,
            HttpHeaders headers,
            HttpCookies cookies,
            int maxRedirects,
            Func<TContent, TData> deserialize
        )
        {
            var response = MakeRequest<RestResponse<TContent, TData>, TContent>(
                endpoint,
                method,
                content,
                headers,
                cookies,
                maxRedirects,
                new RestResponse<TContent, TData>()
            );
            if (response.HasError)
                return response;

            // Only deserialize when HTTP call succeeded, even with non 2XX code
            try
            {
                response.Data = deserialize(response.Content);
            }
            catch (Exception e) // TODO: Not a good practice, see how to catch only specific exceptions
            {
                response.Error = e;
            }

            return response;
        }

        private TResponse MakeRequest<TResponse, TContent>(
            string endpoint,
            HttpMethod method,
            HttpContent content,
            HttpHeaders headers,
            HttpCookies cookies,
            int maxRedirects,
            TResponse allocatedResult
        )
            where TResponse : RestResponse<TContent>
        {
            var uri = MakeAbsoluteUri(endpoint);
            var allHeaders = Signer.Sign(uri, method, DefaultHeaders.Merge(headers), content);
            var allCookies = DefaultCookies.Merge(cookies);

            StringBuilder logBuilder = null;
            if (Logger != null)
            {
                logBuilder = new StringBuilder();
                logBuilder.AppendLine($"Request: {method} {uri}");
                foreach (var (k, v) in allHeaders)
                    logBuilder.AppendLine($"Header: {k}: {v}");
                // TODO: Enable when needed
                if (WarningFree.AlwaysFalse)
                    foreach (var (k, v) in allCookies)
                        logBuilder.AppendLine($"Cookie: {k}: {v}");
                if (content != null)
                    logBuilder.AppendLine($"Content: {content.ReadAsStringAsync().GetAwaiter().GetResult()}");
                logBuilder.AppendLine($"Max redirects: {maxRedirects}");
                Logger.Log(logBuilder.ToString());
            }

            Transport.MakeRequest(uri, method, content, allHeaders, allCookies, maxRedirects, allocatedResult);

            if (Logger != null)
            {
                logBuilder!.Clear();
                logBuilder.AppendLine($"Response: {allocatedResult.StatusCode} {allocatedResult.Error?.Message}");
                if (allocatedResult.Headers != null)
                    foreach (var (k, v) in allocatedResult.Headers)
                        logBuilder.AppendLine($"Header: {k}: {v}");
                // TODO: Enable when needed
                if (WarningFree.AlwaysFalse)
                    if (allocatedResult.Cookies != null)
                        foreach (var (k, v) in allocatedResult.Cookies)
                            logBuilder.AppendLine($"Cookie: {k}: {v}");
                logBuilder.AppendLine($"Content: {allocatedResult.Content}");
                Logger.Log(logBuilder.ToString());
            }

            return allocatedResult;
        }

        private HttpContent ToJsonContent(PostParameters parameters)
        {
            return new StringContent(JsonParametersToString(parameters), Encoding.UTF8, "application/json");
        }

        private string JsonParametersToString(PostParameters parameters)
        {
            if (parameters == JsonBlank)
                return "";

            if (parameters == JsonNull)
                return "null";

            return SerializeToJson(parameters);
        }

        private static HttpContent ToFormContent(PostParameters parameters)
        {
            // TODO: FormUrlEncodedContent doesn't add "charset=utf-8"
            //       Maybe a better option would be to send it as StringContent with forced encoding.
            return new FormUrlEncodedContent(parameters.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value.ToString())));
        }

        private string SerializeToJson<T>(T value)
        {
            return UseSystemJson ? System.Text.Json.JsonSerializer.Serialize(value) : JsonConvert.SerializeObject(value);
        }

        private T DeserializeFromJson<T>(string json)
        {
            return UseSystemJson ? System.Text.Json.JsonSerializer.Deserialize<T>(json) : JsonConvert.DeserializeObject<T>(json);
        }

        //
        // JsonSerializer extensions
        //

#nullable enable

        // TODO: Find a better place for this!
        // TODO: Consider making it non-static and deserializing with the RestClient settings
        public static bool TryDeserialize<T>(string json, [NotNullWhen(true)] out T? result)
            where T : class => TryDeserialize(json, out result, out _);

        public static bool TryDeserialize<T>(string json, [NotNullWhen(true)] out T? result, out System.Text.Json.JsonException? error)
            where T : class
        {
            try
            {
                result = System.Text.Json.JsonSerializer.Deserialize<T>(json);
                error = null;
                return result != null;
            }
            catch (System.Text.Json.JsonException e)
            {
                result = null;
                error = e;
            }

            return false;
        }

#nullable restore

        private const int MaxRedirects = 3;
        private const int NoRedirects = 0;
    }
}
