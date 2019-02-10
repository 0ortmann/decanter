from __future__ import division
from brothon import bro_log_reader
import pandas as pd


class BroParser:
    """ Parse Bro log files """

    def __init__(self):
        pass

    def parseFile(self, filename, json=False):
        """ Creates a pandas dataframe from given brofile

            Parameters
            ----------
            filename : string
                Path to file to be parsed

            Returns
            -------
            result : pd.DataFrame
                Pandas dataframe containing bro log file
            """
        df = None
        if not json:
            bro_log = bro_log_reader.BroLogReader(filename)
            df = pd.DataFrame(bro_log.readrows())
        else:
            df = pd.read_json(filename, lines=True)
            df.rename(
                index=str,
                columns={
                    'client_header_names': 'header_values'},
                inplace=True)
        df['header_values'] = df['header_values'].apply(
            self.__parseHeaderValues__)
        return df

    def parseLine(self, line):
        """ Creates a pandas dataframe from given json logline

            Parameters
            ----------
            line : dict
                zeek json log line

            Returns
            -------
            result : pd.DataFrame
                Pandas dataframe containing zeek log line
            """
        df = pd.DataFrame.from_dict(line, orient='index')
        df = df.transpose()
        df.rename(
            index=str,
            columns={
                'client_header_names': 'header_values'},
            inplace=True)
        df['header_values'] = df['header_values'].apply(
            self.__parseHeaderValues__)
        return df

    def __parseHeaderValues__(self, headerValues):
        """ Parse header values from BRO encoding to dictionary.

            Parameters
            ----------
            headerValues : string
                header value in bro format

            Returns
            -------
            result : dict
                header value in dict format

            """
        try:
            return dict((x, y) for x, y in list(map(lambda entry: (entry.split('||')[
                        0].lower(), entry.split('||')[1].replace('\\x2c', ',')), headerValues.split(','))))
        except BaseException:
            return {}
