# -*- coding: utf-8 -*-
############################################
#   Author : Hao                           #
#   Date   : Tue, 02 Apr 2019 09:50:26 GMT #
############################################
import base64
import datetime
import json

import requests
import hmac
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib.parse import unquote as unescape
def build_common_headers(config,method, path, customHeaders={}, unescaped_queries=None):
    GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
    headers = {
        'content-type': 'application/json',
        'date':datetime.datetime.utcnow().strftime(GMT_FORMAT)
    }
    if customHeaders:
        headers.update(customHeaders)
    # Sign the request and set the signature to headers.
    headers['authorization'] =sign_request(config,method, path, headers, unescaped_queries)
    return headers

def sign_request(config, method, unescaped_path, headers, unescaped_queries=None):
    content_md5 = headers.get('content-md5', '')
    content_type = headers.get('content-type', '')
    access_key_secret = config.get('access_key_secret','')
    date = headers.get('date', '')
    canonical_headers = build_canonical_headers(headers)
    canonical_resource = unescaped_path
    # if isinstance(unescaped_queries, dict):
    #     canonical_resource = get_sign_resource(unescaped_path, unescaped_queries)
    string_to_sign = '\n'.join(
        [method.upper(), content_md5, content_type, date, canonical_headers + canonical_resource])
    h = hmac.new(access_key_secret.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha256)
    signature = 'FC ' + config.get('access_key_id') + ':' + base64.b64encode(h.digest()).decode('utf-8')
    print(signature)
    return signature

def get_sign_resource(unescaped_path, unescaped_queries):
    if not isinstance(unescaped_queries, dict):
        raise TypeError("`dict` type required for queries")
    params = []
    for key, values in unescaped_queries.items():
        if isinstance(values, str):
            params.append('%s=%s' % (key, values))
            continue
        if len(values) > 0:
            for value in values:
                params.append('%s=%s' % (key, value))
        else:
            params.append('%s' % key)
    params.sort()
    resource = unescaped_path + '\n' + '\n'.join(params)
    return resource

def build_canonical_headers(headers):
    canonical_headers = []
    for k, v in headers.items():
        lower_key = k.lower()
        if lower_key.startswith('x-fc-'):
            canonical_headers.append((lower_key, v))
    canonical_headers.sort(key=lambda x: x[0])
    if canonical_headers:
        return '\n'.join(k + ':' + v for k, v in canonical_headers) + '\n'
    else:
        return ''

def do_http_request(config, method, path, headers={}, params=None, body=None):
    params = {} if params is None else params
    if not isinstance(params, dict):
        raise TypeError('`None` or `dict` required for params')
    path = '/{0}/proxy/{1}/{2}{3}'.format(config.get('api_version'), config.get('service_name'),config.get('function_name'), path if path != "" else "/")
    url = '{0}{1}'.format(config.get('endpoint'), path)
    headers = build_common_headers(config,method, unescape(path), headers, params)
    r = requestWithTry(method, url, headers=headers, params=params, data=body, timeout=config.get('timeout'))
    return r

def requestWithTry(method, url, **kwargs):
    retries = 5
    backoff_factor = 1
    status_forcelist = (500, 502, 504)
    with requests.Session() as session:
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session.request(method=method, url=url, **kwargs)

config = {
    'endpoint':'',
    'access_key_id' :'',
    'access_key_secret':'',
    'api_version' : '2016-08-15',
    'service_name' : '',
    'function_name': '',
    'timeout': 60
}
params = {
    'one': '1',
    'two': '2',
}
response=do_http_request(config=config,method='GET', path='/', params=params)
print(json.loads(response.content))