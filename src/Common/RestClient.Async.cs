// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.Common;

using HttpCookies = Dictionary<string, string>;
using HttpHeaders = Dictionary<string, string>;
using PostParameters = Dictionary<string, object>;

internal partial class RestClient
{
    //
    // GET string
    //

    public Task<RestResponse<string>> GetAsync(string endpoint, CancellationToken cancellationToken) =>
        GetAsync(endpoint, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> GetAsync(string endpoint, HttpHeaders headers, CancellationToken cancellationToken) =>
        GetAsync(endpoint, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> GetAsync(string endpoint, HttpHeaders headers, HttpCookies cookies, CancellationToken cancellationToken) =>
        GetAsync(endpoint, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> GetAsync(
        string endpoint,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) => MakeRequestAsync<string>(endpoint, HttpMethod.Get, null, headers ?? NoHeaders, cookies ?? NoCookies, maxRedirects, cancellationToken);

    //
    // GET binary
    //

    public Task<RestResponse<byte[]>> GetBinaryAsync(string endpoint, CancellationToken cancellationToken) =>
        GetBinaryAsync(endpoint, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<byte[]>> GetBinaryAsync(string endpoint, HttpHeaders headers, CancellationToken cancellationToken) =>
        GetBinaryAsync(endpoint, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<byte[]>> GetBinaryAsync(
        string endpoint,
        HttpHeaders headers,
        HttpCookies cookies,
        CancellationToken cancellationToken
    ) => GetBinaryAsync(endpoint, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<byte[]>> GetBinaryAsync(
        string endpoint,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) => MakeRequestAsync<byte[]>(endpoint, HttpMethod.Get, null, headers ?? NoHeaders, cookies ?? NoCookies, maxRedirects, cancellationToken);

    //
    // GET string with deserialization
    //

    public Task<RestResponse<string, T>> GetAsync<T>(string endpoint, CancellationToken cancellationToken) =>
        GetAsync<T>(endpoint, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> GetAsync<T>(string endpoint, HttpHeaders headers, CancellationToken cancellationToken) =>
        GetAsync<T>(endpoint, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> GetAsync<T>(
        string endpoint,
        HttpHeaders headers,
        HttpCookies cookies,
        CancellationToken cancellationToken
    ) => GetAsync<T>(endpoint, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> GetAsync<T>(
        string endpoint,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) =>
        MakeRequestAsync<string, T>(
            endpoint,
            HttpMethod.Get,
            null,
            headers ?? NoHeaders,
            cookies ?? NoCookies,
            maxRedirects,
            DeserializeFromJson<T>,
            cancellationToken
        );

    //
    // POST JSON, receive string
    //

    public Task<RestResponse<string>> PostJsonAsync(string endpoint, CancellationToken cancellationToken) =>
        PostJsonAsync(endpoint, JsonBlank, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostJsonAsync(string endpoint, PostParameters parameters, CancellationToken cancellationToken) =>
        PostJsonAsync(endpoint, parameters, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostJsonAsync(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        CancellationToken cancellationToken
    ) => PostJsonAsync(endpoint, parameters, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostJsonAsync(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        CancellationToken cancellationToken
    ) => PostJsonAsync(endpoint, parameters, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostJsonAsync(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) => MakeRequestAsync<string>(endpoint, HttpMethod.Post, ToJsonContent(parameters), headers, cookies, maxRedirects, cancellationToken);

    //
    // POST JSON, receive JSON
    //

    public Task<RestResponse<string, T>> PostJsonAsync<T>(string endpoint, CancellationToken cancellationToken) =>
        PostJsonAsync<T>(endpoint, JsonBlank, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostJsonAsync<T>(string endpoint, PostParameters parameters, CancellationToken cancellationToken) =>
        PostJsonAsync<T>(endpoint, parameters, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostJsonAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        CancellationToken cancellationToken
    ) => PostJsonAsync<T>(endpoint, parameters, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostJsonAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        CancellationToken cancellationToken
    ) => PostJsonAsync<T>(endpoint, parameters, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostJsonAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) =>
        MakeRequestAsync<string, T>(
            endpoint,
            HttpMethod.Post,
            ToJsonContent(parameters),
            headers,
            cookies,
            maxRedirects,
            DeserializeFromJson<T>,
            cancellationToken
        );

    //
    // POST form (string)
    //

    public Task<RestResponse<string>> PostFormAsync(string endpoint, PostParameters parameters, CancellationToken cancellationToken) =>
        PostFormAsync(endpoint, parameters, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostFormAsync(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        CancellationToken cancellationToken
    ) => PostFormAsync(endpoint, parameters, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostFormAsync(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        CancellationToken cancellationToken
    ) => PostFormAsync(endpoint, parameters, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string>> PostFormAsync(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) => MakeRequestAsync<string>(endpoint, HttpMethod.Post, ToFormContent(parameters), headers, cookies, maxRedirects, cancellationToken);

    //
    // POST form with deserialization
    //

    public Task<RestResponse<string, T>> PostFormAsync<T>(string endpoint, PostParameters parameters, CancellationToken cancellationToken) =>
        PostFormAsync<T>(endpoint, parameters, NoHeaders, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostFormAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        CancellationToken cancellationToken
    ) => PostFormAsync<T>(endpoint, parameters, headers, NoCookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostFormAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        CancellationToken cancellationToken
    ) => PostFormAsync<T>(endpoint, parameters, headers, cookies, MaxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PostFormAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) =>
        MakeRequestAsync<string, T>(
            endpoint,
            HttpMethod.Post,
            ToFormContent(parameters),
            headers ?? NoHeaders,
            cookies ?? NoCookies,
            maxRedirects,
            DeserializeFromJson<T>,
            cancellationToken
        );

    //
    // POST raw
    //

    public Task<RestResponse<string>> PostRawAsync(
        string endpoint,
        string content,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    ) =>
        MakeRequestAsync<string>(
            endpoint,
            HttpMethod.Post,
            new StringContent(content),
            headers ?? NoHeaders,
            cookies ?? NoCookies,
            maxRedirects,
            cancellationToken
        );

    //
    // PUT
    //

    public Task<RestResponse<string>> PutAsync(
        string endpoint,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    ) => MakeRequestAsync<string>(endpoint, HttpMethod.Put, null, headers ?? NoHeaders, cookies ?? NoCookies, maxRedirects, cancellationToken);

    public Task<RestResponse<string, T>> PutAsync<T>(
        string endpoint,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    ) =>
        MakeRequestAsync<string, T>(
            endpoint,
            HttpMethod.Put,
            null,
            headers ?? NoHeaders,
            cookies ?? NoCookies,
            maxRedirects,
            DeserializeFromJson<T>,
            cancellationToken
        );

    //
    // Private
    //

    private Task<RestResponse<TContent>> MakeRequestAsync<TContent>(
        string endpoint,
        HttpMethod method,
        HttpContent content,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    ) =>
        MakeRequestAsync<RestResponse<TContent>, TContent>(
            endpoint,
            method,
            content,
            headers,
            cookies,
            maxRedirects,
            new RestResponse<TContent>(),
            cancellationToken
        );

    private async Task<RestResponse<TContent, TData>> MakeRequestAsync<TContent, TData>(
        string endpoint,
        HttpMethod method,
        HttpContent content,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        Func<TContent, TData> deserialize,
        CancellationToken cancellationToken
    )
    {
        var response = await MakeRequestAsync<RestResponse<TContent, TData>, TContent>(
                endpoint,
                method,
                content,
                headers,
                cookies,
                maxRedirects,
                new RestResponse<TContent, TData>(),
                cancellationToken
            )
            .ConfigureAwait(false);
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

    // TODO: Merge the code with MakeRequest sync version
    private async Task<TResponse> MakeRequestAsync<TResponse, TContent>(
        string endpoint,
        HttpMethod method,
        HttpContent content,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        TResponse allocatedResult,
        CancellationToken cancellationToken
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
            {
                var contentStr = await content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                logBuilder.AppendLine($"Content: {contentStr}");
            }
            logBuilder.AppendLine($"Max redirects: {maxRedirects}");
            Logger.Log(logBuilder.ToString());
        }

        await Transport
            .MakeRequestAsync(uri, method, content, allHeaders, allCookies, maxRedirects, allocatedResult, cancellationToken)
            .ConfigureAwait(false);

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
}
