#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2022 Matteo Golinelli"
__license__ = "MIT"

from urllib.parse import urlparse, urlunparse

import random
import string


class WCDE:
    '''
    This class implements the methods
    to detect Web Cache Deception vulnerabilities
    as described in the paper: "Web Cache Deception
    Escalates!"
    '''
    def __init__(self):
        self.MODES = {
            'PATH_PARAMETER'    : '/',
            'ENCODED_SEMICOLON' : self.encode(';'),    # %3B
            'ENCODED_QUESTION'  : self.encode('?'),    # %3F
            'ENCODED_NEWLINE'   : self.encode('\n'),   # %0A
            'ENCODED_SHARP'     : self.encode('#'),    # %23
            'ENCODED_SLASH'     : self.encode('/'),    # %2F
            'DOUBLE_ENCODED_SEMICOLON': self.encode('%3B'), # %25%33%42
            'DOUBLE_ENCODED_QUESTION':  self.encode('%3F'), # %25%33%46
            'DOUBLE_ENCODED_NEWLINE':   self.encode('%0A'), # %25%30%41
            'DOUBLE_ENCODED_SHARP':     self.encode('%23'), # %25%32%33
            'DOUBLE_ENCODED_SLASH':     self.encode('%2F'), # %25%32%46
            'DOUBLE_ENCODED_NULL':      self.encode('%00'), # %25%30%30
        }
        self.IGNORE_HEADERS = [
            'Cache-Control',
            'X-CCDN-CacheTTL'
        ]
        self.LOGS   = 'logs'
        self.STATS  = 'stats'

    def get_random_string(self, length):
        '''
        Generate a random string of the desired length
        '''
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def generate_attack_url(self, url, mode, extension='.css'):
        '''
        Generate the attack URL including the
        desired path confusion technique in
        the passed URL.

        For different path confusion variations
        the inclusion happens in different places
        of the URL.
        '''
        parsed_url    = urlparse(url)
        random_string = self.get_random_string()
        encoded_character = self.MODES[mode]

        path  = parsed_url.path
        query = parsed_url.query
        # Path parameter / is simply appended at the end
        if mode == 'PATH_PARAMETER':
            if not path.endswith('/'):
                path += encoded_character
            path += f'{random_string}{extension}'

        # Encoded question mark ? is placed before the query string
        elif mode == 'ENCODED_QUESTION':
            path += f'{encoded_character}{query}{random_string}{extension}'
            query = ''

        else:
            path += f'{encoded_character}{random_string}{extension}'

        return urlunparse(
            (parsed_url.scheme, parsed_url.netloc,
            path, parsed_url.params, query, parsed_url.fragment)
        )

    def cache_headers_heuristics(self, headers):
        '''
        Inspects HTTP response headers to heuristically
        determine whether a request is served from the
        origin server or a web cache

        Returns a 'HIT' or 'MISS' for cache and origin
        respectively.
        Returns the value of the cache status header
        if it is present.
        '-' if the status is unknown.
        '''
        cache_status = '-'
        # Start with the most specific headers for HIT
        for header in headers:
            if (
                    'x-drupal-cache' in header.lower() or
                    'x-proxy-cache' in header.lower() or
                    'x-rack-cache' in header.lower() or
                    'cdn_cache' in header.lower() or
                    'cf-cache' in header.lower() or
                    'x-cache' in header.lower() or
                    'x-edge' in header.lower()):
                if (
                        'hit' in headers[header].lower() or
                        'expired' in headers[header].lower() or
                        'cached' in headers[header].lower()):
                    return 'HIT'
        # Then the most specific headers for MISS
        for header in headers:
            if (
                    'x-drupal-cache' in header.lower() or
                    'x-proxy-cache' in header.lower() or
                    'x-rack-cache' in header.lower() or
                    'cdn_cache' in header.lower() or
                    'cf-cache' in header.lower() or
                    'x-cache' in header.lower() or
                    'x-edge' in header.lower()):
                if 'miss' in headers[header].lower():
                    return 'MISS'
                else:
                    cache_status = headers[header]

            # Then the more generic ones
            if (('cache' in header.lower() or
                    'server-timing' in header.lower()) and
                    not any(x.lower() in header.lower() for x in self.IGNORE_HEADERS)
                ):
                if 'hit' in headers[header].lower():
                    return 'HIT'
                elif 'miss' in headers[header].lower():
                    return 'MISS'
                elif 'cached' in headers[header].lower():
                    return 'HIT'
                elif 'caching' in headers[header].lower():
                    return 'MISS'
                elif 'edge' in headers[header].lower():
                    return 'HIT'
                elif 'origin' in headers[header].lower():
                    return 'MISS'
                elif cache_status == '-':
                    cache_status = headers[header]
        return cache_status

    def identicality_checks(self, p1, p2):
        '''
        Compare two web pages.
        Return False is the pages are different
        (i.e., contain dynamic content) 
        True if the pages are 100% identical
        '''
        if p1 == p2:
            return True
        else:
            return False

    def encode(self, s):
        '''
        URL-encode characters or strings
        '''
        return ''.join(['%' + hex(ord(i)).replace('0x', '').upper().zfill(2) for i in s])

    def get_random_string(self, _min=10, _max=20):
        '''
        Generates a random string of random
        length between 10 and 20 characters
        '''
        return ''.join(
            random.choice(string.ascii_lowercase + string.digits + '_')
            for _ in range(random.randint(_min, _max))
        )

    def diff_lines(self, a, b):
        '''
        Returns the lines that differ between two
        multi-lines strings (pages HTML code)
        '''
        a = a.split('\n')
        b = b.split('\n')
        res = ''
        for i in range(min(len(a), len(b))):
            _a, _b = a[i].strip(), b[i].strip()
            if _a == '' and _b == '':
                continue
            if _a != _b:
                res += f'< {_a}\n'
                res += f'> {_b}\n'
        res += '---'
        return res
