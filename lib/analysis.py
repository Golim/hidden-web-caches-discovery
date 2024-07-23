#!/usr/bin/env python3

from scipy import stats

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

class Analysis:
    def __init__(self, request_pairs=10):
        self.request_pairs = request_pairs

    def remove_outliers(self, data, factor=2):
        '''
        Remove the outliers by computing the average and standard deviation of the data
        and removing the data points that are outside the factor * std from the average.
        '''
        average = sum([request_pair['time_diff'] for request_pair in data]) / len(data)
        std = (sum([(request_pair['time_diff'] - average) ** 2 for request_pair in data]) / len(data)) ** 0.5

        # Remove the outliers
        return [request_pair for request_pair in data if abs(request_pair['time_diff'] - average) < factor * std]

    def predict(self, randomized, fixed):
        # Create a local copy of the input data
        _randomized = randomized.copy()
        _fixed = fixed.copy()

        # Remove the outliers from the data
        _randomized = self.remove_outliers(_randomized)
        _fixed = self.remove_outliers(_fixed)

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

    def analyse(self, site, data):
        analysis = {}

        for url in data:
            if url not in analysis:
                analysis[url] = {}
            for extension in data[url]:
                if extension not in analysis[url]:
                    analysis[url][extension] = {}
                for mode in data[url][extension]:
                    if mode not in analysis[url][extension]:
                        analysis[url][extension][mode] = {}

                    if not 'randomized' in data[url][extension][mode] or \
                        not 'fixed' in data[url][extension][mode]:
                        print(f'There is no data for {url} with mode {mode}, extension={extension}')
                        continue

                    print(f'Analizing {url} with mode {mode}, extension={extension}')

                    randomized = []
                    for request_pair in data[url][extension][mode]['randomized']:
                        randomized.append({
                            'time_diff': round(request_pair['time_diff'], 2),
                            'cache_status_1': request_pair['first']['cache_status'],
                            'cache_status_2': request_pair['second']['cache_status'],
                        })

                    fixed = []
                    for request_pair in data[url][extension][mode]['fixed']:
                        fixed.append({
                            'time_diff': round(request_pair['time_diff'], 2),
                            'cache_status_1': request_pair['first']['cache_status'],
                            'cache_status_2': request_pair['second']['cache_status'],
                        })

                    if len(fixed) == 0 or len(randomized) == 0:
                        print(f'No data for site {site}')
                        return

                    statistics_prediction = self.predict(randomized, fixed)
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

                    if sum([1 for request_pair in data[url][extension][mode]['fixed'] if request_pair['second']['cache_status'] == 'HIT']) > \
                        sum([1 for request_pair in data[url][extension][mode]['fixed'] if request_pair['second']['cache_status'] == 'MISS']):
                        label = 'CACHE'

                    analysis[url][extension][mode] = {
                        'label': label,
                        'statistics_prediction': statistics_prediction,
                        'randomized': randomized,
                        'fixed': fixed,
                    }

        return analysis
