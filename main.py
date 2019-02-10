from decanter.bro_parser import BroParser
from decanter.decanter_new import Aggregator
from decanter.evaluation_utils import EvaluationUtils
from decanter.detection import OfflineDetector
import sys
import argparse


class Decanter():

    def __init__(self, training_log=None, testing_log=None,
                 offline=1, is_json=False, csv_path=None):
        self.training_log = training_log
        self.testing_log = testing_log
        self.offline = offline
        self.is_json = is_json
        self.csv_path = csv_path

        self.model = None

    def dumped_fingerprint_analysis(self):
        if self.csv_path is None:
            print('Cannot run without csv data')
            sys.exit(1)

        o = OfflineDetector(self.csv_path)

        # Run detection on the loaded CSV files in path.
        # Files with filename having the string "training" are used for training.
        # Those with "testing" are used for testing.
        alerts, benign = o.run_detection_2()

        # Run the classification performance evaluation.
        e = EvaluationUtils(alerts, benign)
        e.output_requests()
        e.detection_performance_2()

        # Print the unique Fingerprints (i.e., with retraining).
        print("Unique Fingerprints: {}\n".format(len(e.unique_fing)))
        for f in e.unique_fing:
            print(f)

    def log_fingerprint_analysis(self):
        if self.training_log is None or self.testing_log is None:
            print('Cannot run without train and test data')
            sys.exit(1)

        bp = BroParser()
        testing = bp.parseFile(self.testing_log, self.is_json)

        model = self.train()

        # Extract Fingerprints from testing_log
        # If online (i.e., 0), Fingerprints are tested against trained Fingerprints
        # If offline (i.e., 1), testing and training fingerprints are dumped in
        # seperate csv files.
        model.analyze_log(testing)

        e = EvaluationUtils(model.alerts, [])
        e._unique_fingerprints()

        print("Unique Alerts: {}\n".format(len(e.unique_fing)))
        for f in e.unique_fing:
            print(f)

    def train(self):
        print('decanter training...')
        bp = BroParser()
        training = bp.parseFile(self.training_log, self.is_json)

        # offline = 0: any new fingerprints will be tested against trained
        # fingerprints
        decanter_trainer = Aggregator(0, self.offline)

        # train model
        decanter_trainer.analyze_log(training)

        # switch mode to testing
        decanter_trainer.change_mode(1)

        self.model = decanter_trainer

    def test(self, logline):
        bp = BroParser()
        testing = bp.parseLine(logline)

        self.model.analyze_log(testing)

        e = EvaluationUtils(self.model.alerts, [])
        e._unique_fingerprints()

        return e.unique_fing

def main(argv):
    parser = argparse.ArgumentParser(
        description="DECANTeR: DETection of Anomalous outbouNd HTTP Traffic by Passive Application Fingerprinting")
    parser.add_argument(
        'mode',
        type=str,
        default='logs',
        help='csv, logs, continuous - mode to run decanter with')
    parser.add_argument(
        '--csv',
        type=str,
        help='Run the evaluation loading Fingerprints from csv files stored in the selected folder. CSV files containing "training" in the filename will be used to train the fingerprints. CSV files having "testing" in the filename will be used for testing.')
    parser.add_argument(
        '-t',
        '--training',
        type=str,
        help='Bro log file used to train fingerprints.')
    parser.add_argument(
        '-T',
        '--testing',
        type=str,
        help='Bro log file used for testing against trained fingerprints.')
    parser.add_argument(
        '-o',
        '--offline',
        type=int,
        default=1,
        help='Choose 1 if you want to dump the fingerprints extracted from the logs to .csv files. Choose 0 if you want to run the evaluation from the logs. (default=1).')
    parser.add_argument('-j', '--json', type=bool, default=False,
                        help='Define the bro log format. Default is False for normal bro logs.')

    args = parser.parse_args()

    decanter = Decanter(
        args.training,
        args.testing,
        args.offline,
        args.json,
        args.csv)

    if args.mode == 'csv':
        decanter.dumped_fingerprint_analysis()
    elif args.mode == 'logs':
        decanter.log_fingerprint_analysis()
    elif args.mode == 'continuos':
        decanter.train()


if __name__ == "__main__":
    main(sys.argv)
