#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2024 Matteo Golinelli"
__license__ = "MIT"

from tabulate import tabulate
from scipy import stats

import json
import glob
import sys


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


REQUEST_PAIRS = 10
if len(sys.argv) > 2:
    REQUEST_PAIRS = int(sys.argv[2])

def remove_outliers(data, factor=2):
    # Compute the mean and standard deviation of the data
    average = sum([request_pair['time_diff'] for request_pair in data]) / len(data)
    std = (sum([(request_pair['time_diff'] - average) ** 2 for request_pair in data]) / len(data)) ** 0.5

    # Remove the outliers
    return [request_pair for request_pair in data if abs(request_pair['time_diff'] - average) < factor * std]

def predict(randomized, fixed):
    # Create a local copy of the input data
    _randomized = randomized.copy()
    _fixed = fixed.copy()

    # Remove the outliers from the data
    _randomized = remove_outliers(_randomized)
    _fixed = remove_outliers(_fixed)

    if len(_randomized) == 0 or len(_fixed) == 0:
        return

    # Compute the mean and standard deviation of response time differences for randomized and fixed requests
    randomized_average = sum([request_pair['time_diff'] for request_pair in _randomized]) / len(_randomized)
    randomized_std = (sum([(request_pair['time_diff'] - randomized_average) ** 2 for request_pair in _randomized]) / len(_randomized)) ** 0.5

    # Enhance the time difference of negative values to make them more significant
    enhancing_factor = 5

    fixed_average = sum([
            request_pair['time_diff'] for request_pair in _fixed
        ]) / len(_fixed)
    fixed_std = (sum([(
            request_pair['time_diff'] - fixed_average
        ) ** 2 for request_pair in _fixed]) / len(_fixed)) ** 0.5

    if fixed_average > 0:
        return 'NO cache'

    print(f'Randomized average: {randomized_average}, Fixed average: {fixed_average}')
    print(f'Randomized std: {randomized_std}, Fixed std: {fixed_std}')

    # Chose a significance level
    alpha = 0.01

    # Compute the t-test
    t, p = stats.ttest_ind(
        [
            request_pair['time_diff']
                for request_pair in _randomized
        ],
        [
            request_pair['time_diff'] * enhancing_factor if fixed_average < 0  else request_pair['time_diff']
                for request_pair in _fixed
        ],
        equal_var=False)

    print(f't: {t}, p: {p}')

    if p <= alpha:
        return 'CACHE'
    else:
        return 'NO cache'

def main():
    tested = [site.replace('analysis/', '').split(f'-{REQUEST_PAIRS}')[0] for site in glob.glob('analysis/*')]
    filename = sys.argv[1]
    site = filename.split('/')[-1].split('-202')[0]
    if site in tested:
        return

    print(f'Analysing {bcolors.OKBLUE}{site}{bcolors.ENDC}')

    with open(filename, 'r') as f:
        data = json.load(f)

    randomized = []
    for request_pair in data['randomized']:
        randomized.append({
            'time_diff': round(request_pair['time_diff'], 2),
            'cache_status_1': request_pair['first']['cache_status'],
            'cache_status_2': request_pair['second']['cache_status'],
        })

    fixed = []
    for request_pair in data['fixed']:
        fixed.append({
            'time_diff': round(request_pair['time_diff'], 2),
            'cache_status_1': request_pair['first']['cache_status'],
            'cache_status_2': request_pair['second']['cache_status'],
        })

    if len(fixed) == 0 or len(randomized) == 0:
        print(f'No data for site {site}')
        return

    statistics_prediction = predict(randomized, fixed)
    if not statistics_prediction:
        return

    # Generate the sample of data
    label = 'Unknown'

    # If there are cache status headers, we can predict the label
    if any([request_pair['cache_status_1'] == 'HIT' or request_pair['cache_status_2'] == 'HIT' for request_pair in randomized]) or \
        any([request_pair['cache_status_1'] == 'HIT' or request_pair['cache_status_2'] == 'HIT' for request_pair in fixed]) or \
        any([request_pair['cache_status_1'] == 'MISS' or request_pair['cache_status_2'] == 'MISS' for request_pair in randomized]) or \
        any([request_pair['cache_status_1'] == 'MISS' or request_pair['cache_status_2'] == 'MISS' for request_pair in fixed]):
        label = 'NO cache'

    if sum([1 for request_pair in data['fixed'] if request_pair['second']['cache_status'] == 'HIT']) > \
        sum([1 for request_pair in data['fixed'] if request_pair['second']['cache_status'] == 'MISS']):
        label = 'CACHE'

    analysis = {
        'label': label,
        'statistics_prediction': statistics_prediction,
        'randomized': randomized,
        'fixed': fixed,
    }

    with open(f'analysis/{site}-{REQUEST_PAIRS}.json', 'w') as f:
        json.dump(analysis, f, indent=4)

    SPACING = 17
    # Log the data
    print('=' * SPACING + ' Time differences w/o a cache ' + '=' * SPACING)
    print(tabulate(
        analysis['randomized'],
        headers={'time_diff': 'Time difference (ms)', 'cache_status_1': 'Cache Status 1', 'cache_status_2': 'Cache Status 2'},
        tablefmt='orgtbl',
        colalign=('decimal', 'center', 'center'))
    )

    print('=' * SPACING + ' Time differences w/ a cache  ' + '=' * SPACING)
    print(tabulate(
        analysis['fixed'],
        headers={'time_diff': 'Time difference (ms)', 'cache_status_1': 'Cache Status 1', 'cache_status_2': 'Cache Status 2'},
        tablefmt='orgtbl',
        colalign=('decimal', 'center', 'center'))
    )

    print('=' * 22 + '  Prediction  ' + '=' * 17)
    print(tabulate(
        [
            ['Label', label],
            ['Statistics', f'{bcolors.OKCYAN}{statistics_prediction}{bcolors.ENDC}'],
        ],
        headers=['', 'Cache Status'],
        tablefmt='orgtbl',
        colalign=('left', 'center'))
    )

if __name__ == '__main__':
    main()
