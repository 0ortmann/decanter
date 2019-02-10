DECANTeR
========

This is a fork of the original DECANTeR implementation. Find the corresponding scientific paper here [DEteCtion of Anomalous outbouNd HTTP TRaffic by Passive Application Fingerprinting](https://research.utwente.nl/en/publications/decanter-detection-of-anomalous-outbound-http-traffic-by-passive-). Credits to the original authors:

*Bortolameotti, R., van Ede, T. S., Caselli, M., Everts, M. H., Hartel, P. H., Hofstede, R., ... Peter, A. (2017). DECANTeR: DEteCtion of Anomalous outbouNd HTTP TRaffic by Passive Application Fingerprinting. In ACSAC 2017, Proceedings of the 33rd Annual Computer Security Applications Conference (pp. 373-386) https://doi.org/10.1145/3134600.3134605* 


## Purpose of this fork

This is a rewrite in `python 3` with a streamlined build process via `pip` and a containerized application.

## Data Format

DECANTeR uses [zeek IDS](https://www.zeek.org/) http logs as input for anomaly detection. I extended it such that it is capable of using raw zeek-formatted logs as well as line based json.

## Run

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Dependencies & Installation

Ensure you have installed the latest [Python 3.x](https://www.python.org/downloads/) and [Pip 3](https://pip.pypa.io/en/stable/installing/). Upgrade Pip's package listing:

On Linux or MacOS:

    $ pip install -U pip

On Windows:

    $ python -m pip install -U pip

Before installing the DECANTeR package, make sure the following Python packages are installed:

* [brothon](https://github.com/Kitware/BroThon)
* [editdistance](https://pypi.python.org/pypi/editdistance)
* [IPy](https://pypi.python.org/pypi/IPy/)
* [networkx](https://pypi.python.org/pypi/networkx/)
* [pandas](http://pandas.pydata.org/)
* [urllib](https://docs.python.org/3/library/urllib.html)

All relevant dependencies are bundled in the `requirements.txt` file. Install it with:

    $ pip install -r requirements.txt

### Generating Bro log files

To use our implementation of DECANTeR, you need `zeek` .log files (either `zeek` log format or json). Therefore, you need to [install zeek](https://docs.zeek.org/en/stable/install/index.html). Once `zeek` is installed, you will find a binary called `bro`.


Run the following command to generate a `zeek` .log file that is parsable by our implementation of DECANTeR. The command instructs `zeek` to analyze the `example.pcap` file and to load the custom script `decanter_dump_input.bro`.

    $ bro -r example.pcap decanter_dump_input.bro

The output file _decanter.log_ is the log file parsable by our implementation. This command will always write to the same filename, therefore you must later rename the output file to avoid overwriting existing logs.

**Note:** If you have installed `zeek` by compiling it yourself, you will probably have to change the first two lines of our custom script `decanter_dump_input.bro` accordingly to your installation path.


### DECANTeR Functionalities

At the current stage, our implementation provides two type of analysis:
- **Live analysis**: you can provide a training and testing log file, and DECANTeR will analyze the data and print the alerts (if any).
- **Offline analysis**: you can provide a path folder containing a set of .csv files containing the fingerprints (previously dumped by DECANTeR, see below). DECANTeR will use for training all .csv files that have "training" in their filename, and it will use for testing all .csv files having "testing" in their filename.
  - Dump fingerprints from .log files to .csv: you can provide one file for training and one file for testing, and DECANTeR will generate the fingerprints and dump them to .csv files. This is an intermediary step to run the offline analysis.

### Usage Examples

Some `zeek` logs are provided in the [test-data](test-data) folder; examples on how to use DECANTeR to run Live and Offline analyses:

#### Example of Live analysis

    $ python3 main.py --training test-data/user/log/riccardo_linux_training_16-01.log --testing test-data/user/log/riccardo_linux_testing_18-01.log -o 0
    $ python3 main.py --training test-data/malware/vm7_decanter.log --testing test-data/malware/exiltration_logs/URSNIF_386.pcap.decanter.log -o 0

#### Example of Offline analysis

    $ python3 main.py --csv test-data/user/csv/

#### Example of dumping CSV files and running offline analysis

1. Dump fingerprints in csv files.

        $ python3 main.py --training test-data/user/log/riccardo_linux_training_16-01.log --testing test-data/user/log/riccardo_linux_testing_18-01.log -o 1

2. Analyze the fingerprints.

        $ python2 main.py --csv ./
