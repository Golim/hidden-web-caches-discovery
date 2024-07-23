# Hidden Web Caches Discovery

This repository includes the code used in our research published in the paper "*Hidden Web Caches Discovery*" at the 27th International Symposium on Research in Attacks, Intrusions and Defenses (**RAID 2024**).

A preprint of the paper is available [here](https://golim.github.io).

Once the paper will be published, it will be available at the following DOI: [10.1145/3678890.3678931](https://doi.org/10.1145/3678890.3678931).

## How to use

To launch the experiment on a single website, use the `hidden-web-caches-discovery.py` script. The script requires the domain name of the website to test as an argument. For example:

```bash
python experiment.py --max 10 --domains 10 --requests 10 --analyse --target target.tld
```

Where:

- `--max` is the maximum number of URLs to test for each domain/subdomain (default: 10).
- `--domains` is the maximum number of domains/subdomains to test (default: 2).
- `--requests` is the number of request pairs to send to the target website.
- `--analyse` is a flag to enable the analysis of the data collected during the experiment.
- `--target` is the domain name of the website to test.

Other options are available, use the `--help` parameter to see the full list of options.

## Structure of the repository

The main scripts are located in the root folder of the repository. The scripts are:

- `hidden-web-caches-discovery.py`: the script used to perform the main experiment of the paper on the Tranco Top 50k (section 6.2 in the paper).
- `preliminary-experiment.py`: the script used to perform the preliminary experiment on the Tranco Top 10k (section 6.1 in the paper).
- `experiment-wcd.py`: the script used to test websites for Web Cache Deception vulnerabilities using our novel time-based technique (section 7.2 in the paper).

### `lib/` folder

The lib folder includes several libraries used in the code. The libraries are:

- `cache_buster.py`: implements the cache-busting techniques.
- `crawler.py`: implements the crawling functionalities and a browser class based on Python requests.
- `wcde.py`: implements the functionalities to perform Web Cache Deception attacks (attack URL generation, cache headers heuristics and identicality checks) as described in the paper *[Web Cache Deception Escalates!](https://www.usenix.org/conference/usenixsecurity22/presentation/mirheidari)*.
- `analysis.py`: implements the functionalities to analyse the data collected during the Web Cache Deception vulnerabilities experiments.
- `h2time.py`: it is a modified version of the Python implementation [by DistriNet](https://github.com/DistriNet/timeless-timing-attacks) of the **Timeless Timing Attack** technique presented in their paper [Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections](https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem).

### `utils/` folder

The utils folder includes several utilities used during our research to launch the experiments and analyse the data collected. The utilities are:

- `experiment-launcher.py`: script to launch the main experiment on the Tranco Top 50k.
- `preliminary-experiment-launcher.py`: script to launch the preliminary experiment on the Tranco Top 10k.
- `experiment-wcd-launcher.py`: script to launch the Web Cache Deception vulnerabilities experiment.
- `analyse-experiment.py`: script to analyse the data collected during the preliminary and main experiments.
