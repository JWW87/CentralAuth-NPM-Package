var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { buildUrl, createConfig, createInterceptors, getParseAs, mergeConfigs, mergeHeaders, setAuthParams, } from './utils';
export const createClient = (config = {}) => {
    let _config = mergeConfigs(createConfig(), config);
    const getConfig = () => (Object.assign({}, _config));
    const setConfig = (config) => {
        _config = mergeConfigs(_config, config);
        return getConfig();
    };
    const interceptors = createInterceptors();
    const request = (options) => __awaiter(void 0, void 0, void 0, function* () {
        var _a, _b, _c;
        const opts = Object.assign(Object.assign(Object.assign({}, _config), options), { fetch: (_b = (_a = options.fetch) !== null && _a !== void 0 ? _a : _config.fetch) !== null && _b !== void 0 ? _b : globalThis.fetch, headers: mergeHeaders(_config.headers, options.headers) });
        if (opts.security) {
            yield setAuthParams(Object.assign(Object.assign({}, opts), { security: opts.security }));
        }
        if (opts.body && opts.bodySerializer) {
            opts.body = opts.bodySerializer(opts.body);
        }
        // remove Content-Type header if body is empty to avoid sending invalid requests
        if (opts.body === undefined || opts.body === '') {
            opts.headers.delete('Content-Type');
        }
        const url = buildUrl(opts);
        const requestInit = Object.assign({ redirect: 'follow' }, opts);
        let request = new Request(url, requestInit);
        for (const fn of interceptors.request._fns) {
            if (fn) {
                request = yield fn(request, opts);
            }
        }
        // fetch must be assigned here, otherwise it would throw the error:
        // TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation
        const _fetch = opts.fetch;
        let response = yield _fetch(request);
        for (const fn of interceptors.response._fns) {
            if (fn) {
                response = yield fn(response, request, opts);
            }
        }
        const result = {
            request,
            response,
        };
        if (response.ok) {
            if (response.status === 204 ||
                response.headers.get('Content-Length') === '0') {
                return opts.responseStyle === 'data'
                    ? {}
                    : Object.assign({ data: {} }, result);
            }
            const parseAs = (_c = (opts.parseAs === 'auto'
                ? getParseAs(response.headers.get('Content-Type'))
                : opts.parseAs)) !== null && _c !== void 0 ? _c : 'json';
            if (parseAs === 'stream') {
                return opts.responseStyle === 'data'
                    ? response.body
                    : Object.assign({ data: response.body }, result);
            }
            let data = yield response[parseAs]();
            if (parseAs === 'json') {
                if (opts.responseValidator) {
                    yield opts.responseValidator(data);
                }
                if (opts.responseTransformer) {
                    data = yield opts.responseTransformer(data);
                }
            }
            return opts.responseStyle === 'data'
                ? data
                : Object.assign({ data }, result);
        }
        let error = yield response.text();
        try {
            error = JSON.parse(error);
        }
        catch (_d) {
            // noop
        }
        let finalError = error;
        for (const fn of interceptors.error._fns) {
            if (fn) {
                finalError = (yield fn(error, response, request, opts));
            }
        }
        finalError = finalError || {};
        if (opts.throwOnError) {
            throw finalError;
        }
        // TODO: we probably want to return error and improve types
        return opts.responseStyle === 'data'
            ? undefined
            : Object.assign({ error: finalError }, result);
    });
    return {
        buildUrl,
        connect: (options) => request(Object.assign(Object.assign({}, options), { method: 'CONNECT' })),
        delete: (options) => request(Object.assign(Object.assign({}, options), { method: 'DELETE' })),
        get: (options) => request(Object.assign(Object.assign({}, options), { method: 'GET' })),
        getConfig,
        head: (options) => request(Object.assign(Object.assign({}, options), { method: 'HEAD' })),
        interceptors,
        options: (options) => request(Object.assign(Object.assign({}, options), { method: 'OPTIONS' })),
        patch: (options) => request(Object.assign(Object.assign({}, options), { method: 'PATCH' })),
        post: (options) => request(Object.assign(Object.assign({}, options), { method: 'POST' })),
        put: (options) => request(Object.assign(Object.assign({}, options), { method: 'PUT' })),
        request,
        setConfig,
        trace: (options) => request(Object.assign(Object.assign({}, options), { method: 'TRACE' })),
    };
};
//# sourceMappingURL=client.js.map