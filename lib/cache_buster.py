#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"


from urllib.parse import urlparse, urlunparse

import random
import string


class CacheBuster:
    """
    This clsas implements the methods to
    cache-bust a request.
    """

    TEST_HEADERS = [
        'Origin', 'User-Agent', 'X-Forwarded-Host',
        'X-Forwarded-For', 'X-Forwarded-Proto',
        'X-Method-Override', 'X-Forwarded-Scheme',
    ]

    _cache_busters = []

    def __init__(self, site, headers={}, cookies={}):
        self.site = site
        self.headers = headers
        self.cookies = cookies

    def generate_random_string(self, length):
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def get_unique_cache_buster(self, length=5):
        '''
        Return a unique random cache-buster
        of the specified length (default=5)
        '''
        cache_buster = ''
        while cache_buster in self._cache_busters or cache_buster == '':
            cache_buster = self.generate_random_string(length)
        self._cache_busters.append(cache_buster)

        return cache_buster

    def cache_bust_header(self, site, header, value):
        '''
        Modify the value of the header
        to get a modification that
        cache-busts the request
        '''

        if header.lower() == 'user-agent':
            return value + ' ' + self.get_unique_cache_buster()

        if header.lower() == 'accept-encoding':
            if value == '':
                return '' + self.get_unique_cache_buster()
            return value + ', ' + self.get_unique_cache_buster()

        if header.lower() == 'accept':
            accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,' + self.get_unique_cache_buster()
            return accept

        if header.lower() == 'accept-language':
            return f'it-IT,it;q=0.9,{self.get_unique_cache_buster()}'

        if header.lower() == 'origin':
            return f'https://{site}/{self.get_unique_cache_buster()}'

        if header.lower() == 'x-forwarded-scheme' or (
                'x-' in header.lower() and 
                'forwarded-proto' in header.lower()):
            return f'http{self.get_unique_cache_buster()}'

        if 'x-' in header.lower() and 'method' in header.lower():
            return f'GET{self.get_unique_cache_buster()}'

        if 'x-' in header.lower() and (
            'forwarded' in header.lower() or
            '-url' in header.lower()
            ) or header.lower() == 'forwarded':
            return f'{self.get_unique_cache_buster()}.{site}'

        else:
            return self.get_unique_cache_buster()

    def cache_bust_cookies(self, cookies, cache_bust_all=True):
        '''
        Add a random and unique cache-busting
        cookie and, if cache_bust_all is True,
        add the cache-buster to all the cookies
        '''
        cache_buster = self.get_unique_cache_buster()

        if cache_bust_all:
            for cookie in cookies:
                cookies[cookie] = cookies[cookie] + ',' + cache_buster

        cookies[cache_buster] = cache_buster
        return cookies

    def cache_bust_query(self, url):
        """
        Return a URL with a random and unique
        cache busting parameter.
        Moreover, if the Vary header is present,
        add a random and unique value for each
        of the headers specified in the Vary header.
        """
        cache_buster = self.get_unique_cache_buster()

        parsed = urlparse(url)
        if parsed.query == '':
            query = cache_buster + '=' + cache_buster
        query = parsed.query + ('&' if parsed.query else '') + cache_buster + '=' + cache_buster

        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

    def cache_bust_path(self, url):
        '''
        Return a URL with a random and unique
        cache busting path.
        '''
        cache_buster = self.get_unique_cache_buster()

        parsed = urlparse(url)
        if parsed.path.endswith('/'):
            path = parsed.path + cache_buster
        else:
            path = parsed.path + '/' + cache_buster

        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))

    def cache_bust_request(self, url, headers={}, cookies={}, vary='', path=False):
        '''
        Apply all the cache-busting techniques
        to the request
        '''
        site = urlparse(url).netloc

        # Cache-bust the path if requested
        if path:
            url = self.cache_bust_path(url)

        # Cache-bust the query string
        url = self.cache_bust_query(url)

        # Cache bust all the headers to cache-bust
        for header in self.TEST_HEADERS:
            if header in headers:
                headers[header] = self.cache_bust_header(site, header, headers[header])
            else:
                headers[header] = self.cache_bust_header(site, header, '')

        # Cache-bust the cookies
        cookies = self.cache_bust_cookies(cookies)

        # Cache-bust the headers in the vary, if present
        for header in vary.split(','):
            header = header.strip().lower()
            if any(header in h.lower() for h in self.TEST_HEADERS) or header == 'cookie':
                continue

            else:
                headers[header] = self.cache_bust_header(site, header, headers[header] if header in headers else '')

        return url, headers, cookies
