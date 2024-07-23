#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2024 Matteo Golinelli"
__license__ = "MIT"

from lib.h2time import H2Request, H2Time
from lib.crawler import Browser, Crawler
from lib.cache_buster import CacheBuster
from lib.analysis import Analysis
from lib.wcde import WCDE

from requests.exceptions import SSLError, ConnectionError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader
from urllib.parse import urlparse, urlunparse

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

    parser.add_argument('-n', '--requests', default=10,
        help=f'Number of request pairs to send to the target website (default: {10})')

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
    statistics['URLs'] = []
    statistics['vulnerable'] = False

    crawler = Crawler(site=SITE, max=int(args.max), max_domains=int(args.domains))

    EXTENSIONS = ['.css']
    MODES = ['PATH_PARAMETER', 'ENCODED_QUESTION', 'ENCODED_SEMICOLON']
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

    browser = Browser(headers=headers, cookies=cookies)
    cache_buster = CacheBuster(SITE, headers, cookies)

    sent_requests = {}

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

            # Check if the response gets cached: we need a direct HIT or a "MISS + HIT" pair
            cache_status = wcde.cache_headers_heuristics(response.headers)
            if cache_status != '-':
                statistics['cache_headers'] = True

            if url not in sent_requests:
                sent_requests[url] = {}

            # Test for WCD, using Timing Attacks
            for extension in EXTENSIONS:
                if extension not in sent_requests[url]:
                    sent_requests[url][extension] = {}
                for mode in MODES:
                    if statistics['vulnerable']:
                        # If this mode was already tested and found vulnerable, skip it
                        if url in statistics['analysis'] and \
                            extension in statistics['analysis'][url] and \
                            mode in statistics['analysis'][url][extension]:
                            continue
                    if mode not in sent_requests[url][extension]:
                        sent_requests[url][extension][mode] = {}

                    # At first, we need to check if the attack URL returns dynamic content
                    attack_url1 = wcde.generate_attack_url(url, mode, extension)
                    attack_url2 = wcde.generate_attack_url(url, mode, extension)

                    response1 = browser.get(attack_url1, headers=headers, allow_redirects=True)
                    response2 = browser.get(attack_url2, headers=headers, allow_redirects=True)
                    if wcde.identicality_checks(response1, response2):
                        logger.debug(f'Attack URLs returned identical responses. Skipping.')
                        continue

                    logger.info(f'Testing {url} with mode: {mode} and extension: {extension}')

                    logger.info(f'Sending {num_requests} requests with randomized cache-busting')
                    # First: send num_requests all with randomized cache-busting
                    for _ in range(num_requests):
                        url1 = url2 = url
                        url1, headers1, _ = cache_buster.cache_bust_request(
                            url1, headers=headers,
                            vary=response.headers.get('vary') if 'vary' in response.headers else '')

                        url2, headers2, _ = cache_buster.cache_bust_request(
                            url2, headers=headers,
                            vary=response.headers.get('vary') if 'vary' in response.headers else '')

                        logger.debug(f'Cache-busted URL 1: {url1}. Cache-busted URL 2: {url2}')

                        request1 = H2Request('GET', url1, headers=headers1)
                        request2 = H2Request('GET', url2, headers=headers2)

                        following_redirects = True # True to enter the while loop
                        redirects_followed = 0
                        while following_redirects and redirects_followed < 5:
                            following_redirects = False
                            with H2Time(request1, request2, num_request_pairs=1) as h2time:
                                try:
                                    results = h2time.run_attack()
                                except Exception as e:
                                    logger.error(f'Error: {e}')
                                    logger.error(traceback.format_exc())
                                    break
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
                                            logger.debug(f'Redirect loop detected: {response_headers1[":status"]} {response_headers1["location"]}')

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

                                    if 'randomized' not in sent_requests[url][extension][mode]:
                                        sent_requests[url][extension][mode]['randomized'] = []
                                    sent_requests[url][extension][mode]['randomized'].append({
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

                    logger.info(f'Sending {num_requests} requests with a WCD payloaded request in each pair')
                    # Next: send num_requests where in each pair:
                    # - one request has a randomized cache-busting
                    # - one request has always the same attack URL with a WCD payload

                    attack_url = wcde.generate_attack_url(url, mode, extension)
                    # Send a first request to the attack URL in an attempt to make it cached
                    attack_url_response = browser.get(attack_url, headers=headers, allow_redirects=True)
                    if attack_url_response.url != attack_url:
                        if extension not in attack_url_response:
                            logger.info(f'Received a redirection to a non-payloaded URL: {attack_url_response.url}')
                            continue
                        else:
                            attack_url = attack_url_response.url
                    time.sleep(1)

                    for _ in range(num_requests):
                        url1 = url
                        url1, headers1, _ = cache_buster.cache_bust_request(
                            url1, headers=headers,
                            vary=response.headers.get('vary') if 'vary' in response.headers else '')

                        logger.debug(f'Cache-busted URL 1: {url1}. Attack URL: {attack_url}')

                        request1 = H2Request('GET', url1, headers=headers1)
                        request2 = H2Request('GET', attack_url, headers=headers)

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

                                        if extension not in response_headers2['location']:
                                            logger.info(f'Detected redirect to a non-WCD-payloaded URL')

                                        # Check for redirect loops
                                        if url1 == response_headers1['location'] or \
                                            url2 == response_headers2['location']:
                                            logger.debug(f'Redirect loop detected: {response_headers1[":status"]} {response_headers1["location"]}')

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

                                    if 'fixed' not in sent_requests[url][extension][mode]:
                                        sent_requests[url][extension][mode]['fixed'] = []
                                    sent_requests[url][extension][mode]['fixed'].append({
                                        'time_diff': time_diff,
                                        'first': {
                                            'url': url1,
                                            'status_code': response_headers1[':status'],
                                            'cache_status': cache_status1,
                                            'headers': dict(response_headers1),
                                        },
                                        'second': {
                                            'url': attack_url,
                                            'status_code': response_headers2[':status'],
                                            'cache_status': cache_status2,
                                            'headers': dict(response_headers2),
                                        }
                                    })
                            time.sleep(0.5)

                    analysis = Analysis().analyse(SITE, sent_requests)
                    if not analysis:
                        continue

                    statistics['analysis'] = analysis

                    for _url in analysis:
                        for _extension in analysis[_url]:
                            for _mode in analysis[_url][_extension]:
                                try:
                                    if analysis[_url][_extension][_mode]['statistics_prediction'] == 'CACHE':
                                        statistics['vulnerable'] = True
                                        logger.info(f'Vulnerable URL: {_url}')
                                        break
                                except Exception as e:
                                    pass


                    logger.info(f'Finished sending {num_requests} requests with a WCD payloaded request in each pair')

            # Save the sent requests to a file
            date_time = time.strftime('%Y-%m-%d-%H-%M-%S')
            filename = f'output/{SITE}-{date_time}.json'
            with open(filename, 'w') as f:
                json.dump(sent_requests, f, indent=4)
                print(f'Output saved to {filename}')

            statistics['tested'] = True
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
