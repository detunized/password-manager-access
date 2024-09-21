// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

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

    public Task<RestResponse<string, T>> GetAsync<T>(
        string endpoint,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    ) =>
        MakeRequestAsync<string, T>(
            endpoint,
            HttpMethod.Get,
            null,
            headers ?? NoHeaders,
            cookies ?? NoCookies,
            maxRedirects,
            JsonConvert.DeserializeObject<T>,
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
            JsonConvert.DeserializeObject<T>,
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

    public async Task<RestResponse<string, T>> PostFormAsync<T>(
        string endpoint,
        PostParameters parameters,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    )
    {
        return await MakeRequestAsync<string, T>(
                endpoint,
                HttpMethod.Post,
                ToFormContent(parameters),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                JsonConvert.DeserializeObject<T>,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    //
    // POST raw
    //

    public async Task<RestResponse<string>> PostRawAsync(
        string endpoint,
        string content,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    )
    {
        return await MakeRequestAsync<string>(
                endpoint,
                HttpMethod.Post,
                new StringContent(content),
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    //
    // PUT
    //

    public async Task<RestResponse<string>> PutAsync(
        string endpoint,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    )
    {
        return await MakeRequestAsync<string>(
                endpoint,
                HttpMethod.Put,
                null,
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    public async Task<RestResponse<string, T>> PutAsync<T>(
        string endpoint,
        HttpHeaders headers = null,
        HttpCookies cookies = null,
        int maxRedirects = MaxRedirects,
        CancellationToken cancellationToken = default
    )
    {
        return await MakeRequestAsync<string, T>(
                endpoint,
                HttpMethod.Put,
                null,
                headers ?? NoHeaders,
                cookies ?? NoCookies,
                MaxRedirects,
                JsonConvert.DeserializeObject<T>,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    //
    // Private
    //

    private async Task<RestResponse<TContent>> MakeRequestAsync<TContent>(
        string endpoint,
        HttpMethod method,
        HttpContent content,
        HttpHeaders headers,
        HttpCookies cookies,
        int maxRedirects,
        CancellationToken cancellationToken
    )
    {
        return await MakeRequestAsync<RestResponse<TContent>, TContent>(
                endpoint,
                method,
                content,
                headers,
                cookies,
                maxRedirects,
                new RestResponse<TContent>(),
                cancellationToken
            )
            .ConfigureAwait(false);
    }

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
        await Transport.MakeRequestAsync(
            uri,
            method,
            content,
            Signer.Sign(uri, method, DefaultHeaders.Merge(headers), content),
            DefaultCookies.Merge(cookies),
            maxRedirects,
            allocatedResult,
            cancellationToken
        );

        return allocatedResult;
    }
}
