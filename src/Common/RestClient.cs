// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using H = System.Net.Http;

namespace PasswordManagerAccess.Common
{
    using PostParameters = Dictionary<string, object>;
    using HttpHeaders = Dictionary<string, string>;
    using HttpCookies = Dictionary<string, string>;
    using SendAsyncType = Func<H.HttpRequestMessage, Task<H.HttpResponseMessage>>;

    internal class RestResponse
    {
        public HttpStatusCode StatusCode { get; internal set; }
        public string Content { get; internal set; }
        public Exception Error { get; internal set; }
        public Dictionary<string, string> Cookies { get; internal set; }
        public Uri RequestUri { get; internal set; }

        // On HTTP 2xx and no exceptions
        public bool IsSuccessful => IsHttpOk && !HasError;

        // On HTTP 2xx
        public bool IsHttpOk => (int)StatusCode / 100 == 2;

        // On HTTP other than 2xx, but not other exceptions
        public bool IsHttpError => !IsHttpOk && !HasError;

        // On other error
        public bool HasError => Error != null;

        public bool IsNetworkError => HasError && Error is HttpRequestException;
    }

    internal class RestResponse<T>: RestResponse
    {
        public T Data { get; internal set; }
    }

    internal class RestMessageHandler: H.HttpMessageHandler
    {
        public RestMessageHandler(SendAsyncType sendAsync)
        {
            _sendAsync = sendAsync;
        }

        protected override Task<H.HttpResponseMessage> SendAsync(H.HttpRequestMessage request,
                                                                 CancellationToken cancellationToken)
        {
            return _sendAsync(request);
        }

        private readonly SendAsyncType _sendAsync;
    }

    internal class RestClient: IDisposable
    {
        public readonly H.HttpClient Http;
        public readonly string BaseUrl;

        public RestClient(string baseUrl = ""): this(MakeDefaultHttpClient(), baseUrl)
        {
        }

        public RestClient(SendAsyncType sendAsync, string baseUrl = ""): this(MakeHttpClient(sendAsync), baseUrl)
        {
        }

        //
        // GET
        //

        public RestResponse Get(string endpoint, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest(endpoint,
                               H.HttpMethod.Get,
                               null,
                               headers ?? NoHeaders,
                               cookies ?? NoCookies,
                               MaxRedirects);
        }

        public RestResponse<T> Get<T>(string endpoint, HttpHeaders headers = null, HttpCookies cookies = null)
        {
            return MakeRequest<T>(endpoint,
                                  H.HttpMethod.Get,
                                  null,
                                  headers ?? NoHeaders,
                                  cookies ?? NoCookies,
                                  MaxRedirects,
                                  JsonConvert.DeserializeObject<T>);
        }

        //
        // POST JSON
        //

        public RestResponse PostJson(string endpoint,
                                     PostParameters parameters,
                                     HttpHeaders headers = null,
                                     HttpCookies cookies = null)
        {
            return MakeRequest(endpoint,
                               H.HttpMethod.Post,
                               ToJsonContent(parameters),
                               headers ?? NoHeaders,
                               cookies ?? NoCookies,
                               MaxRedirects);
        }

        public RestResponse<T> PostJson<T>(string endpoint,
                                           PostParameters parameters,
                                           HttpHeaders headers = null,
                                           HttpCookies cookies = null)
        {
            return MakeRequest(endpoint,
                               H.HttpMethod.Post,
                               ToJsonContent(parameters),
                               headers ?? NoHeaders,
                               cookies ?? NoCookies,
                               MaxRedirects,
                               JsonConvert.DeserializeObject<T>);
        }

        //
        // POST form
        //

        public RestResponse PostForm(string endpoint,
                                     PostParameters parameters,
                                     HttpHeaders headers = null,
                                     HttpCookies cookies = null)
        {
            return MakeRequest(endpoint,
                               H.HttpMethod.Post,
                               ToFormContent(parameters),
                               headers ?? NoHeaders,
                               cookies ?? NoCookies,
                               NoRedirects,
                               () => new RestResponse());
        }

        public RestResponse<T> PostForm<T>(string endpoint,
                                           PostParameters parameters,
                                           HttpHeaders headers = null,
                                           HttpCookies cookies = null)
        {
            return MakeRequest(endpoint,
                               H.HttpMethod.Post,
                               ToFormContent(parameters),
                               headers ?? NoHeaders,
                               cookies ?? NoCookies,
                               NoRedirects,
                               JsonConvert.DeserializeObject<T>);
        }

        //
        // Internal
        //

        internal Uri MakeAbsoluteUri(string endpoint)
        {
            // It's allowed to have no base URL and then the endpoint is an absolute URL
            // The Uri constructor should take care of broken URL formats and throw.
            if (BaseUrl.IsNullOrEmpty())
                return new Uri(endpoint);

            return new Uri(new Uri(BaseUrl), endpoint);
        }

        //
        // Private
        //

        private static H.HttpClient MakeDefaultHttpClient()
        {
            var handler = new HttpClientHandler() { UseCookies = false, AllowAutoRedirect = false };
            return new H.HttpClient(handler, true);
        }

        private static H.HttpClient MakeHttpClient(SendAsyncType sendAsync)
        {
            return new H.HttpClient(new RestMessageHandler(sendAsync), true);
        }

        private RestClient(H.HttpClient http, string baseUrl)
        {
            Http = http;
            BaseUrl = baseUrl.TrimEnd('/');
        }

        private RestResponse<T> MakeRequest<T>(string endpoint,
                                               H.HttpMethod method,
                                               H.HttpContent content,
                                               HttpHeaders headers,
                                               HttpCookies cookies,
                                               int maxRedirectCount,
                                               Func<string, T> deserialize)
        {
            var response = MakeRequest(endpoint,
                                       method,
                                       content,
                                       headers,
                                       cookies,
                                       maxRedirectCount,
                                       () => new RestResponse<T>());
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

        private RestResponse MakeRequest(string endpoint,
                                         H.HttpMethod method,
                                         H.HttpContent content,
                                         HttpHeaders headers,
                                         HttpCookies cookies,
                                         int maxRedirectCount)
        {
            return MakeRequest(endpoint,
                               method,
                               content,
                               headers,
                               cookies,
                               maxRedirectCount,
                               () => new RestResponse());
        }

        private TResponse MakeRequest<TResponse>(string endpoint,
                                                 H.HttpMethod method,
                                                 H.HttpContent content,
                                                 HttpHeaders headers,
                                                 HttpCookies cookies,
                                                 int maxRedirectCount,
                                                 Func<TResponse> responseFactory) where TResponse : RestResponse
        {
            return MakeRequest(MakeAbsoluteUri(endpoint),
                               method,
                               content,
                               headers,
                               cookies,
                               maxRedirectCount,
                               responseFactory);
        }

        private TResponse MakeRequest<TResponse>(Uri uri,
                                                 H.HttpMethod method,
                                                 H.HttpContent content,
                                                 HttpHeaders headers,
                                                 HttpCookies cookies,
                                                 int maxRedirectCount,
                                                 Func<TResponse> responseFactory) where TResponse: RestResponse
        {
            var result = responseFactory();
            try
            {
                var request = new H.HttpRequestMessage(method, uri) { Content = content };

                // Set headers
                foreach (var h in headers)
                    request.Headers.Add(h.Key, h.Value);

                // Set cookies
                var cookieHeaderValue = string.Join("; ", cookies.Select(x => $"{x.Key}={x.Value}"));
                request.Headers.TryAddWithoutValidation("Cookie", cookieHeaderValue);

                // Don't use .Result here but rather .GetAwaiter().GetResult()
                // It produces a nicer call stack and no AggregateException nonsense
                // https://stackoverflow.com/a/36427080/362938
                var response = Http.SendAsync(request).GetAwaiter().GetResult();

                var responseCookies = ParseResponseCookies(response, uri);
                var allCookies = cookies.Merge(responseCookies);

                // Redirect if still possible (HTTP Status 300..399)
                if ((int)response.StatusCode / 100 == 3 && maxRedirectCount > 0)
                    return MakeRequest(response.Headers.Location, // TODO: The URL might be relative!
                                       method,
                                       content,
                                       headers,
                                       allCookies,
                                       maxRedirectCount - 1,
                                       responseFactory);

                // Set up the result
                result.RequestUri = uri;
                result.StatusCode = response.StatusCode;
                result.Content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                result.Cookies = allCookies;
            }
            catch (H.HttpRequestException e)
            {
                result.Error = e;
            }

            return result;
        }

        private static H.HttpContent ToJsonContent(PostParameters parameters)
        {
            return new H.StringContent(JsonConvert.SerializeObject(parameters),
                                       Encoding.UTF8,
                                       "application/json");
        }

        private static H.HttpContent ToFormContent(PostParameters parameters)
        {
            // TODO: FormUrlEncodedContent doesn't add "charset=utf-8"
            //       Maybe a better option would be to send it as StringContent with forced encoding.
            return new H.FormUrlEncodedContent(
                parameters.Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value.ToString())));
        }

        private static Dictionary<string, string> ParseResponseCookies(H.HttpResponseMessage response, Uri uri)
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
            return jar.GetCookies(uri)
                .Cast<Cookie>()
                .ToDictionary(x => x.Name, x => x.Value);
        }

        private const string SetCookieHeader = "Set-Cookie";
        private static readonly HttpHeaders NoHeaders = new HttpHeaders();
        private static readonly HttpCookies NoCookies = new HttpCookies();
        private const int MaxRedirects = 3;
        private const int NoRedirects = 0;

        //
        // IDsposable
        //

        private bool disposedValue = false; // To detect redundant calls

        void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Http.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
    }
}
