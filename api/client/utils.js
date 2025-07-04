var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
import { getAuthToken } from '../core/auth';
import { jsonBodySerializer } from '../core/bodySerializer';
import { serializeArrayParam, serializeObjectParam, serializePrimitiveParam, } from '../core/pathSerializer';
const PATH_PARAM_RE = /\{[^{}]+\}/g;
const defaultPathSerializer = ({ path, url: _url }) => {
    let url = _url;
    const matches = _url.match(PATH_PARAM_RE);
    if (matches) {
        for (const match of matches) {
            let explode = false;
            let name = match.substring(1, match.length - 1);
            let style = 'simple';
            if (name.endsWith('*')) {
                explode = true;
                name = name.substring(0, name.length - 1);
            }
            if (name.startsWith('.')) {
                name = name.substring(1);
                style = 'label';
            }
            else if (name.startsWith(';')) {
                name = name.substring(1);
                style = 'matrix';
            }
            const value = path[name];
            if (value === undefined || value === null) {
                continue;
            }
            if (Array.isArray(value)) {
                url = url.replace(match, serializeArrayParam({ explode, name, style, value }));
                continue;
            }
            if (typeof value === 'object') {
                url = url.replace(match, serializeObjectParam({
                    explode,
                    name,
                    style,
                    value: value,
                    valueOnly: true,
                }));
                continue;
            }
            if (style === 'matrix') {
                url = url.replace(match, `;${serializePrimitiveParam({
                    name,
                    value: value,
                })}`);
                continue;
            }
            const replaceValue = encodeURIComponent(style === 'label' ? `.${value}` : value);
            url = url.replace(match, replaceValue);
        }
    }
    return url;
};
export const createQuerySerializer = ({ allowReserved, array, object, } = {}) => {
    const querySerializer = (queryParams) => {
        const search = [];
        if (queryParams && typeof queryParams === 'object') {
            for (const name in queryParams) {
                const value = queryParams[name];
                if (value === undefined || value === null) {
                    continue;
                }
                if (Array.isArray(value)) {
                    const serializedArray = serializeArrayParam(Object.assign({ allowReserved, explode: true, name, style: 'form', value }, array));
                    if (serializedArray)
                        search.push(serializedArray);
                }
                else if (typeof value === 'object') {
                    const serializedObject = serializeObjectParam(Object.assign({ allowReserved, explode: true, name, style: 'deepObject', value: value }, object));
                    if (serializedObject)
                        search.push(serializedObject);
                }
                else {
                    const serializedPrimitive = serializePrimitiveParam({
                        allowReserved,
                        name,
                        value: value,
                    });
                    if (serializedPrimitive)
                        search.push(serializedPrimitive);
                }
            }
        }
        return search.join('&');
    };
    return querySerializer;
};
/**
 * Infers parseAs value from provided Content-Type header.
 */
export const getParseAs = (contentType) => {
    var _a;
    if (!contentType) {
        // If no Content-Type header is provided, the best we can do is return the raw response body,
        // which is effectively the same as the 'stream' option.
        return 'stream';
    }
    const cleanContent = (_a = contentType.split(';')[0]) === null || _a === void 0 ? void 0 : _a.trim();
    if (!cleanContent) {
        return;
    }
    if (cleanContent.startsWith('application/json') ||
        cleanContent.endsWith('+json')) {
        return 'json';
    }
    if (cleanContent === 'multipart/form-data') {
        return 'formData';
    }
    if (['application/', 'audio/', 'image/', 'video/'].some((type) => cleanContent.startsWith(type))) {
        return 'blob';
    }
    if (cleanContent.startsWith('text/')) {
        return 'text';
    }
};
export const setAuthParams = (_a) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    var { security } = _a, options = __rest(_a, ["security"]);
    for (const auth of security) {
        const token = yield getAuthToken(auth, options.auth);
        if (!token) {
            continue;
        }
        const name = (_b = auth.name) !== null && _b !== void 0 ? _b : 'Authorization';
        switch (auth.in) {
            case 'query':
                if (!options.query) {
                    options.query = {};
                }
                options.query[name] = token;
                break;
            case 'cookie':
                options.headers.append('Cookie', `${name}=${token}`);
                break;
            case 'header':
            default:
                options.headers.set(name, token);
                break;
        }
        return;
    }
});
export const buildUrl = (options) => {
    const url = getUrl({
        baseUrl: options.baseUrl,
        path: options.path,
        query: options.query,
        querySerializer: typeof options.querySerializer === 'function'
            ? options.querySerializer
            : createQuerySerializer(options.querySerializer),
        url: options.url,
    });
    return url;
};
export const getUrl = ({ baseUrl, path, query, querySerializer, url: _url, }) => {
    const pathUrl = _url.startsWith('/') ? _url : `/${_url}`;
    let url = (baseUrl !== null && baseUrl !== void 0 ? baseUrl : '') + pathUrl;
    if (path) {
        url = defaultPathSerializer({ path, url });
    }
    let search = query ? querySerializer(query) : '';
    if (search.startsWith('?')) {
        search = search.substring(1);
    }
    if (search) {
        url += `?${search}`;
    }
    return url;
};
export const mergeConfigs = (a, b) => {
    var _a;
    const config = Object.assign(Object.assign({}, a), b);
    if ((_a = config.baseUrl) === null || _a === void 0 ? void 0 : _a.endsWith('/')) {
        config.baseUrl = config.baseUrl.substring(0, config.baseUrl.length - 1);
    }
    config.headers = mergeHeaders(a.headers, b.headers);
    return config;
};
export const mergeHeaders = (...headers) => {
    const mergedHeaders = new Headers();
    for (const header of headers) {
        if (!header || typeof header !== 'object') {
            continue;
        }
        const iterator = header instanceof Headers ? header.entries() : Object.entries(header);
        for (const [key, value] of iterator) {
            if (value === null) {
                mergedHeaders.delete(key);
            }
            else if (Array.isArray(value)) {
                for (const v of value) {
                    mergedHeaders.append(key, v);
                }
            }
            else if (value !== undefined) {
                // assume object headers are meant to be JSON stringified, i.e. their
                // content value in OpenAPI specification is 'application/json'
                mergedHeaders.set(key, typeof value === 'object' ? JSON.stringify(value) : value);
            }
        }
    }
    return mergedHeaders;
};
class Interceptors {
    constructor() {
        this._fns = [];
    }
    clear() {
        this._fns = [];
    }
    getInterceptorIndex(id) {
        if (typeof id === 'number') {
            return this._fns[id] ? id : -1;
        }
        else {
            return this._fns.indexOf(id);
        }
    }
    exists(id) {
        const index = this.getInterceptorIndex(id);
        return !!this._fns[index];
    }
    eject(id) {
        const index = this.getInterceptorIndex(id);
        if (this._fns[index]) {
            this._fns[index] = null;
        }
    }
    update(id, fn) {
        const index = this.getInterceptorIndex(id);
        if (this._fns[index]) {
            this._fns[index] = fn;
            return id;
        }
        else {
            return false;
        }
    }
    use(fn) {
        this._fns = [...this._fns, fn];
        return this._fns.length - 1;
    }
}
// do not add `Middleware` as return type so we can use _fns internally
export const createInterceptors = () => ({
    error: new Interceptors(),
    request: new Interceptors(),
    response: new Interceptors(),
});
const defaultQuerySerializer = createQuerySerializer({
    allowReserved: false,
    array: {
        explode: true,
        style: 'form',
    },
    object: {
        explode: true,
        style: 'deepObject',
    },
});
const defaultHeaders = {
    'Content-Type': 'application/json',
};
export const createConfig = (override = {}) => (Object.assign(Object.assign(Object.assign({}, jsonBodySerializer), { headers: defaultHeaders, parseAs: 'auto', querySerializer: defaultQuerySerializer }), override));
//# sourceMappingURL=utils.js.map