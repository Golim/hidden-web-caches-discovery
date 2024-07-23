#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2024 Matteo Golinelli"
__license__ = "MIT"

from lib.h2time import H2Request, H2Time
from lib.cache_buster import CacheBuster
from lib.crawler import Browser, Crawler
from lib.wcde import WCDE

from requests.exceptions import SSLError, ConnectionError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader
from urllib.parse import urlparse, urlunparse

import subprocess
import traceback
import argparse
import logging
import random
import json
import time
import sys
import os
import re

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'

# Global variables
statistics = {}

def save_dictionaries(site, crawler):
    """
    Save the dictionaries to files.
    """
    global statistics

    logs = {
        'queue':   crawler.queue,
        'visited': crawler.visited_urls
    }

    with open(f'logs/{site}-logs.json', 'w') as f:
        json.dump(logs, f)
    with open(f'stats/{site}-stats.json', 'w') as f:
        json.dump(statistics, f)


def get_dictionaries(site, crawler):
    """
    Load the dictionaries from the files.
    """
    global statistics, visited_urls, queue

    try:
        if os.path.exists(f'logs/{site}-logs.json'):
            with open(f'logs/{site}-logs.json', 'r') as f:
                logs = json.load(f)
                queue = logs['queue']
                visited_urls = logs['visited']

                crawler.set_visited_urls(visited_urls)
                crawler.set_queue(queue)
    except Exception as e:
        logging.error(f'ERROR: {e}')
    try:
        if os.path.exists(f'stats/{site}-stats.json'):
            with open(f'stats/{site}-stats.json', 'r') as f:
                statistics = json.load(f)
    except:
        pass


# =============================================================================
# =================================== MAIN ====================================
# =============================================================================

def main():
    logging.basicConfig()

    logger = logging.getLogger('main')
    logger.setLevel(logging.INFO)

    logging.getLogger('hpack').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(prog='tta.py',
        description='Implementation of the detection methodology for ' + \
                    'web caches in a target website based on Timing Attacks.')

    parser.add_argument('-t', '--target',
        help='Target website', required=True)
    
    parser.add_argument('-r', '--retest', action='store_true',
        help='Retest the URLs that were already tested')

    parser.add_argument('-n', '--requests', default=5,
        help='Number of request pairs to send to the target website')

    parser.add_argument('-c', '--cookie',
        help='Cookies JSON file to use for the requests')

    parser.add_argument('-m', '--max', default=10,
        help=f'Maximum number of URLs to test for each domain/subdomain (default: {10})')

    parser.add_argument('-d', '--domains', default=2,
        help=f'Maximum number of domains/subdomains to test (default: {2})')
    
    parser.add_argument('-x', '--exclude', default='',
        help='Exclude URLs containing the specified regex(es) ' + \
            f'(use commas to separate multiple regexes).')

    parser.add_argument('-D', '--debug',    action='store_true',
        help='Enable debug mode')

    parser.add_argument('-a', '--analyse',    action='store_true',
        help='Analyse the results of the experiment directly')

    parser.add_argument('-R', '--reproducible', action='store_true',
        help='Use a seed for the random number generator to make the results reproducible')

    args = parser.parse_args()
    wcde = WCDE()

    SITE = args.target.strip()
    num_requests = int(args.requests)

    if args.debug:
        logger.setLevel(logging.DEBUG)
        pass

    if args.cookie:
        cookies_file_name = args.cookie

        with open(cookies_file_name, 'r') as f:
            cookies = json.load(f)
    else:
        cookies = {}

    if not os.path.exists('logs'):
        os.mkdir('logs')
    if not os.path.exists('stats'):
        os.mkdir('stats')
    if not os.path.exists('output'):
        os.mkdir('output')
    if not os.path.exists('analysis'):
        os.mkdir('analysis')

    if args.reproducible:
        random.seed(42)
    else:
        logger.info('Using true random numbers')

    statistics['site'] = SITE
    statistics['cache_headers'] = False
    statistics['tested'] = False

    crawler = Crawler(site=SITE, max=int(args.max), max_domains=int(args.domains))

    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'DNT': '1',
        'Sec-GPC': '1'
    }

    logger.info(f'Started testing site: {SITE}')
    logger.info(f'Request pairs: {num_requests}')

    # Load the dictionaries from the files if they exist
    if not args.retest:
        get_dictionaries(SITE, crawler)

    for scheme in ['https']:
        crawler.add_to_queue(f'{scheme}://{SITE}/')
        crawler.add_to_queue(f'{scheme}://www.{SITE}/')

    if not crawler.should_continue():
        logger.info('Limit reached. Exiting.')
        sys.exit(0)

    if args.cookie:
        logger.info('Using provided cookies to create the victim\'s session.')

    strong_cache_busting = False # also cache-bust the path (probably leading to a 404 Not Found response)
    static_file_extension = False # add a static file extension to the path (trying to exploit WCD)

    browser = Browser(headers=headers, cookies=cookies)
    cache_buster = CacheBuster(SITE, headers, cookies)

    while crawler.should_continue():
        try:
            url = crawler.get_url_from_queue()

            if url is None:
                break

            if crawler.is_visited(url):
                continue

            if args.exclude:
                if any(re.search(regex.strip(), url) for regex in args.exclude.split(',')):
                    continue

            parsed = urlparse(url)
            if any(parsed.path.endswith(ext) for ext in crawler.EXCLUDED_EXTENSIONS):
                continue

            logger.info(f'Visiting URL: {url}')

            # Request the URL
            try:
                response = browser.get(url, timeout=60)
            except (SSLError, ConnectionError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader) as e:
                logger.error(f'ERROR: {url} -> {e}')
                if not 'errors' in statistics:
                    statistics['errors'] = []
                statistics['errors'].append({
                    'url': url,
                    'type': type(e).__name__,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })
                continue

            links = crawler.get_links(response.url, response.text)
            for link in links:
                crawler.add_to_queue(link)

            crawler.add_to_visited(url)

            sent_requests = {}

            # Check if the response gets cached: we need a direct HIT or a "MISS + HIT" pair
            cache_status = wcde.cache_headers_heuristics(response.headers)
            if cache_status != '-':
                statistics['cache_headers'] = True

            # Send n request pairs with cache-busting on all elements of the request
            # Requests in randomized should always be MISS
            url1 = url2 = url
            sent_requests['randomized'] = []
            for _ in range(num_requests):
                url1, headers1, _ = cache_buster.cache_bust_request(
                    url1, headers=headers,
                    vary=response.headers.get('vary') if 'vary' in response.headers else '',
                    path=strong_cache_busting)

                url2, headers2, _ = cache_buster.cache_bust_request(
                    url2, headers=headers,
                    vary=response.headers.get('vary') if 'vary' in response.headers else '',
                    path=strong_cache_busting)

                logger.info(f'Cache-busted URL 1: {url1}. Cache-busted URL 2: {url2}')

                request1 = H2Request('GET', url1, headers=headers1)
                request2 = H2Request('GET', url2, headers=headers2)

                following_redirects = True # True to enter the while loop
                redirects_followed = 0
                while following_redirects and redirects_followed < 5:
                    following_redirects = False
                    with H2Time(request1, request2, num_request_pairs=1) as h2time:
                        results = h2time.run_attack()
                        for result in results:
                            (
                                time_diff,
                                response_headers1,
                                response_headers2,
                                response_body1,
                                response_body2
                            ) = result
                            cache_status1 = wcde.cache_headers_heuristics(response_headers1)
                            cache_status2 = wcde.cache_headers_heuristics(response_headers2)

                            if cache_status1 != '-' or \
                                cache_status2 != '-':
                                statistics['cache_headers'] = True

                            # Check if the response is a redirect
                            if response_headers1[':status'] == '301' or \
                                response_headers1[':status'] == '302' or \
                                response_headers2[':status'] == '301' or \
                                response_headers2[':status'] == '302':

                                # Check for redirect loops
                                if url1 == response_headers1['location'] or \
                                    url2 == response_headers2['location']:
                                    logger.info(f'Redirect loop detected: {response_headers1[":status"]} {response_headers1["location"]}')

                                if 'location' in response_headers1:
                                    location1 = response_headers1['location']
                                    if location1.startswith('http'):
                                        url1 = location1
                                    else:
                                        parsed = urlparse(url1)
                                        url1 = urlunparse((
                                            parsed.scheme, parsed.netloc,
                                            location1, parsed.params,
                                            parsed.query, parsed.fragment))
                                if 'location' in response_headers2:
                                    location2 = response_headers2['location']
                                    if location2.startswith('http'):
                                        url2 = location2
                                    else:
                                        parsed = urlparse(url2)
                                        url2 = urlunparse((
                                            parsed.scheme, parsed.netloc,
                                            location2, parsed.params,
                                            parsed.query, parsed.fragment))
                                logger.info(f'Redirect detected: {response_headers1[":status"]} {response_headers1["location"]}')
                                following_redirects = True
                                redirects_followed += 1
                                break

                            sent_requests['randomized'].append({
                                'time_diff': time_diff,
                                'first': {
                                    'url': url1,
                                    'status_code': response_headers1[':status'],
                                    'cache_status': cache_status1,
                                    'headers': dict(response_headers1),
                                },
                                'second': {
                                    'url': url2,
                                    'status_code': response_headers2[':status'],
                                    'cache_status': cache_status2,
                                    'headers': dict(response_headers2),
                                }
                            })
                    time.sleep(0.5)

            # Cache a fixed cache-busting parameter
            time.sleep(1)
            cache_busted_url, cache_busted_headers, _ = cache_buster.cache_bust_request(
                response.url, headers=headers,
                vary=response.headers.get('vary') if 'vary' in response.headers else '',
                path=strong_cache_busting)

            _response = browser.get(cache_busted_url, headers=cache_busted_headers)
            for _ in range(3):
                time.sleep(1)
                _response = browser.get(cache_busted_url, headers=cache_busted_headers)

            logger.info(f'Sent request: {_response.url} to cache a fixed cache-busting parameter and the response cache status is: {wcde.cache_headers_heuristics(_response.headers)}')

            # Send n request pairs with one fixed cache-busting parameter and one randomized
            sent_requests['fixed'] = []
            url1 = url2 = url
            for _ in range(num_requests):
                if 'randomized' not in sent_requests or len(sent_requests['randomized']) == 0:
                    logger.error('No randomized requests were sent')
                    break
                url = sent_requests['randomized'][0]['first']['url']
                if strong_cache_busting:
                    url1 = cache_buster.cache_bust_path(url)
                    url2 = url # Fixed cache-busting parameter: the response comes from the cache
                    headers1 = headers2 = headers
                else:
                    url1, headers1, _ = cache_buster.cache_bust_request(
                        url, headers=headers,
                        vary=response.headers.get('vary') if 'vary' in response.headers else ''
                        ) # Randomized cache-busting parameter: the response comes from the origin
                    url2 = url # Fixed cache-busting parameter: the response comes from the cache
                    headers2 = headers

                logger.info(f'Cache-busted URL 1: {url1}. Fixed URL 2: {url2}')

                following_redirects = True # True to enter the while loop
                redirects_followed = 0
                while following_redirects and redirects_followed < 5:
                    following_redirects = False

                    request1 = H2Request('GET', url1, headers=headers1)
                    request2 = H2Request('GET', url2, headers=headers2)

                    with H2Time(request1, request2, num_request_pairs=1) as h2time:
                        results = h2time.run_attack()
                        if results is None:
                            logger.error('Error while running the attack')
                            break
                        for result in results:
                            (
                                time_diff,
                                response_headers1,
                                response_headers2,
                                response_body1,
                                response_body2
                            ) = result

                            # Check if the response is a redirect
                            if response_headers1[':status'] == '301' or \
                                response_headers1[':status'] == '302' or \
                                response_headers2[':status'] == '301' or \
                                response_headers2[':status'] == '302':

                                # Check for redirect loops
                                if url1 == response_headers1['location'] or \
                                    url2 == response_headers2['location']:
                                    logger.info(f'Redirect loop detected: {response_headers1[":status"]} {response_headers1["location"]}')

                                if 'location' in response_headers1:
                                    location1 = response_headers1['location']
                                    if location1.startswith('http'):
                                        url1 = location1
                                    else:
                                        parsed = urlparse(url1)
                                        url1 = urlunparse((
                                            parsed.scheme, parsed.netloc,
                                            location1, parsed.params,
                                            parsed.query, parsed.fragment))
                                if 'location' in response_headers2:
                                    location2 = response_headers2['location']
                                    if location2.startswith('http'):
                                        url2 = location2
                                    else:
                                        parsed = urlparse(url2)
                                        url2 = urlunparse((
                                            parsed.scheme, parsed.netloc,
                                            location2, parsed.params,
                                            parsed.query, parsed.fragment))
                                logger.info(f'Redirect detected: {response_headers1[":status"]} {response_headers1["location"]}')
                                following_redirects = True
                                redirects_followed += 1
                                break

                            cache_status1 = wcde.cache_headers_heuristics(response_headers1)
                            cache_status2 = wcde.cache_headers_heuristics(response_headers2)

                            if cache_status1 != '-' or \
                                cache_status2 != '-':
                                statistics['cache_headers'] = True

                            sent_requests['fixed'].append({
                                'time_diff': time_diff,
                                'first': {
                                    'url': url1,
                                    'status_code': response_headers1[':status'],
                                    'cache_status': cache_status1,
                                    'headers': dict(response_headers1)
                                },
                                'second': {
                                    'url': url2,
                                    'status_code': response_headers2[':status'],
                                    'cache_status': cache_status2,
                                    'headers': dict(response_headers2)
                                }
                            })

            # Save the sent requests to a file
            date_time = time.strftime('%Y-%m-%d-%H-%M-%S')
            filename = f'output/{SITE}-{date_time}.json'
            with open(filename, 'w') as f:
                json.dump(sent_requests, f, indent=4)
                print(f'Output saved to {filename}')

            statistics['tested'] = True

            if args.analyse:
                subprocess.run(['python3', 'utils/analyse-experiment.py', filename, str(num_requests)])
            else:
                logger.info(f'Finished testing {SITE}, you can analyse the results running the following command:')
                logger.info(f'{bcolors.OKBLUE}python3 utils/analyse-experiment.py {filename} {str(num_requests)}{bcolors.ENDC}')

            # Only test one URL. Comment the following line to test more URLs
            break
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f'ERROR: {url} -> {e}')
            logger.error(traceback.format_exc())
            if not 'errors' in statistics:
                statistics['errors'] = []
            statistics['errors'].append({
                'url': url,
                'type': type(e).__name__,
                'error': str(e),
                'traceback': traceback.format_exc()
            })

    # Save dictionaries to files
    save_dictionaries(SITE, crawler)

# =============================================================================
# =================================== MAIN ====================================
# =============================================================================

if __name__ == '__main__':
    main()
