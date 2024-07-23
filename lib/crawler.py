#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

from urllib.parse import urlparse, urlunparse, urljoin, urldefrag
from bs4 import BeautifulSoup

import requests
import urllib3
import random
import re

class Browser:
    """
    This class implements the methods to
    emulate a browser and make HTTP requests
    using the requests library.

    The browser uses the session object to
    store the cookies and the headers.

    It defines the following methods:
    - `get`: perform a GET request
    - `post`: perform a POST request
    - `get_cookies`: return the cookies of the session
    """
    def __init__(self, cookies=None, headers=None, verify=False):
        """Constructor.

        :param list cookies: the cookies to use
        in the session. It is a list of dictionaries
        that represent the cookies. Each dictionary
        must have the following keys: name, value. The
        other keys are optional and are: domain, path,
        expires, secure, httpOnly.

        :param dict headers: the headers to use
        in the session.
        """
        self.verify = verify
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if cookies:
            self.session = requests.Session()

            cookie_jar = requests.cookies.RequestsCookieJar()
            for cookie in cookies:
                cookie_jar.set(
                    cookie['name'],
                    cookie['value'],
                    domain=(cookie['domain'] if 'domain' in cookie else None),
                    path=(cookie['path'] if 'path' in cookie else None),
                    expires=(cookie['expires'] if 'expires' in cookie else None),
                    secure=(cookie['secure'] if 'secure' in cookie else None),
                    rest={'HttpOnly': (cookie['httpOnly'] if 'httpOnly' in cookie else None)},
                )
            self.session.cookies = cookie_jar
        else:
            self.session = requests.Session()

        if headers:
            self.session.headers.update(headers)

    def get(self, url, **kwargs):
        """
        Perform a GET request.

        :param str url: the URL to request
        """
        if 'referrer' in kwargs:
            self.session.headers.update({'Referer': kwargs['referrer']})
        else:
            self.session.headers.pop('Referer', None)
        kwargs.pop('referrer', None)

        if not self.verify:
            kwargs['verify'] = self.verify
        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        """
        Perform a POST request.

        :param str url: the URL to request
        """
        if 'referrer' in kwargs:
            self.session.headers.update({'Referer': kwargs['referrer']})
        else:
            self.session.headers.pop('Referer', None)
        kwargs.pop('referrer', None)
        return self.session.post(url, **kwargs)

    def get_cookies(self):
        """
        Return the cookies of the session.

        :return: the cookies of the session.
        """
        return self.session.cookies.get_dict()

class Crawler:
    """
    This class implements the methods to
    crawl a website and extract the links
    present in the HTML pages.
    """
    # Avoid accessing potentially large files
    EXCLUDED_EXTENSIONS = set([
        '.webm', '.m3u', '.m3u8', '.pls', '.cue', '.wpl', '.asx', '.xspf', '.mpd'
        '.ps', '.tif', '.tiff', '.ppt', '.pptx', '.xls', '.xlsx', '.dll', '.msi',
        '.iso', '.sql', '.apk', '.jar', '.bmp', '.gif', '.jpg', '.jpeg', '.png',
        '.zip', '.exe', '.dmg', '.doc', '.docx', '.odt', '.pdf', '.rtf', '.tex',
        '.mpg', '.mpeg', '.avi', '.mov', '.wmv', '.flv', '.swf', '.mp4', '.m4v',
        '.mp3', '.ogg', '.wav', '.wma', '.7z', '.rpm', '.gz', '.tar', '.deb',
        '.rar', '.bin', '.tar.gz', '.tar.bz2', '.tar.xz',
    ])

    # Default maximum number of URLs to visit for each domain
    MAX   = 50

    # Maximum number of subdomains to crawl
    MAX_DOMAINS = 10

    def __init__(self, site='', max=MAX, max_domains=MAX_DOMAINS):
        """Constructor.

        :param str site: the domain of of the site to crawl.
        :param int max: the maximum number of URLs to visit for each domain
        :param int max_domains: the maximum number of subdomains to crawl
        """
        self.site = site
        self.queue = {}
        self.visited_urls = {}
        self.max = max
        self.max_domains = max_domains

    def clean_url(self, url):
        """
        Cleans the url

        :param str url: the URL to clean.
        :return: the cleaned URL.
        """
        return url.strip().strip('\n').strip('\r').strip('\t')

    def get_template_url(self, url):
        """
        Returns the template of the passed URL. The template contains:
        - the netloc (domain)
        - the path
        Everything else is removed.

        :param str url: the URL to parse.
        :return: the template of the URL.
        """
        parsed = urlparse(url)
        return urlunparse(('', parsed.netloc, re.sub(r'\d+', '', parsed.path), '', '', ''))

    def get_domain(self, url):
        """
        Returns the domain name of the passed URL.

        :param str url: the URL to parse.
        """
        return urlparse(url).netloc

    def is_internal_url(self, url):
        """
        Returns True if the url is internal to the website.
        Subdomains are considered internal.

        :param str url: the URL to check.
        :return: True if the URL is internal, False otherwise.
        """
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        if parsed.netloc.endswith(self.site):
            return True
        else:
            return False

    def get_links(self, page_url, html, only_internal=True):
        """
        Receives a URL and the body of the web page
        and returns a set of all links found in the
        page that are internal (meaning that are on
        the same site)

        :param str page_url: the URL of the page.
        :param str html: the body of the page.
        :param bool only_internal: if True, only
        internal links are returned.
        :return: a set of links found in the page.
        """
        links = []

        soup = BeautifulSoup(html, 'html.parser')

        for link in soup.find_all('a', href=True):
            url = urljoin(self.clean_url(page_url), self.clean_url(link['href']))

            if 'http' in url and only_internal and self.is_internal_url(url):
                links.append(self.clean_url(urldefrag(url)[0]))

            elif not only_internal:
                _url = self.clean_url(urldefrag(url)[0])
                if any([i in _url for i in self.BLACKLISTED_DOMAINS]):
                    continue

                links.append(_url)

        return links

    def add_to_queue(self, url):
        """
        Add a url to the queue if it is not already in the queue
        and if its template is not already in the visited list.

        :param str url: the URL to add.
        """
        domain = self.get_domain(url)

        if not self.is_visited(url):
            if domain not in self.queue and \
                len(self.queue) < self.max_domains:
                self.queue[domain] = []

            if domain in self.queue and \
                url not in self.queue[domain]:
                self.queue[domain].append(url)

    def add_to_visited(self, url):
        """
        Add a url to the visited list.

        :param str url: the URL to add.
        """
        if not self.is_visited(url):
            domain  = self.get_domain(url)
            if domain not in self.visited_urls:
                self.visited_urls[domain] = []

            template_url = self.get_template_url(url)
            self.visited_urls[domain].append(template_url)

    def is_visited(self, url):
        """
        Return True if the template of the url
        is in the visited list.

        :param str url: the URL to check.
        :return: True if the URL is in the visited list, False otherwise.
        """
        domain = self.get_domain(url)
        if not domain in self.visited_urls:
            return False

        template_url = self.get_template_url(url)
        if template_url is not None and \
            template_url in self.visited_urls[domain]:
            return True
        else:
            return False

    def get_url_from_queue(self, add_to_visited=False):
        """
        Return the first not visited url in the queue
        if the visited list for this domain is not full.

        :param bool add_to_visited: if True, add the returned url to the visited list.
        :return: the first not visited url in the queue.
        """
        domains = list(self.queue.keys())
        random.shuffle(domains)

        for domain in domains:
            # If the visited list for this domain
            # is full, choose a new domain
            if domain in self.visited_urls and \
                len(self.visited_urls[domain]) >= self.max:
                continue
            else:
                # Pop the first url in the queue
                # for this domain
                while len(self.queue[domain]) > 0:
                    url = self.queue[domain].pop(0)
                    if not self.is_visited(url):
                        if add_to_visited:
                            self.add_to_visited(url)
                        return url
        return None

    def should_continue(self):
        """
        Return True if the queue is not empty
        and the visited list is not full.

        :return: True if the queue is not
        empty and the visited list is not full,
        False otherwise.
        """
        for domain in self.queue:
            if domain not in self.visited_urls or \
                (
                    len(self.visited_urls[domain]) < self.max and
                    len(self.queue[domain]) > 0
                    ):
                return True
        return False

    def set_visited_urls(self, visited_urls):
        """
        Set the visited URLs.

        :param dict visited_urls: the visited URLs.
        """
        self.visited_urls = visited_urls

    def set_queue(self, queue):
        """
        Set the queue.

        :param dict queue: the queue.
        """
        self.queue = queue
