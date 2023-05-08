"""
Module that contains CMSWebWrapper
"""

import logging
import json
import os
import time
try:
    from http.client import HTTPSConnection
except ImportError:
    from httplib import HTTPSConnection


class CMSWebWrapper():
    """
    CMSWebWrapper handles all communication with cmsweb
    It requires paths to grid user certificate and grid user key files
    """

    __cache = {}

    def __init__(self, cert_file, key_file):
        self.cert_file = cert_file
        self.key_file = key_file

    def __get_connection(self):
        """
        Return a HTTPSConnection to cmsweb.cern.ch
        """
        if self.cert_file is None or self.key_file is None:
            raise Exception('Missing user certificate or user key')

        return HTTPSConnection('cmsweb.cern.ch',
                               port=443,
                               cert_file=self.cert_file,
                               key_file=self.key_file,
                               timeout=120)

    def get(self, path, cache=True):
        """
        Make a simple GET request
        Add Accept: application/json headers
        """
        logging.info('Will try to GET %s', path)
        if cache and path in self.__cache:
            logging.info('Found %s response in cache', path)
            return self.__cache[path]

        connection = self.__get_connection()
        connection.request('GET', path, headers={'Accept': 'application/json'})
        response = connection.getresponse()
        if response.status != 200:
            logging.error('Problems (%d) with %s: %s', response.status, path, response.read())
            connection.close()
            return None

        decoded_response = response.read().decode('utf-8')
        if cache:
            self.__cache[path] = decoded_response

        connection.close()
        return decoded_response

    def get_big_file(self, path, filename=None):
        """
        Download files chunk by chunk
        """
        logging.info('Will try to download file %s', path)
        if filename is None:
            filename = path.split('/')[-1]
            logging.info('Using file name %s for %s', filename, path)

        if os.path.isfile(filename):
            logging.info('File %s already exists', filename)
            return filename

        connection = self.__get_connection()
        connection.request('GET', path)
        response = connection.getresponse()
        chunk_size = 1024 * 1024 * 8  # 8 megabytes
        with open(filename, 'wb') as output_file:
            total_chunk_size = 0
            start_time = time.time()
            while True:
                chunk = response.read(chunk_size)
                if chunk:
                    output_file.write(chunk)
                    output_file.flush()
                    total_chunk_size += len(chunk)
                else:
                    break

            end_time = time.time()
            speed = (total_chunk_size / (1024.0 * 1024.0)) / (end_time - start_time)
            logging.info('Downloaded %.2fMB in %.2fs. Speed %.2fMB/s',
                         total_chunk_size / (1024.0 * 1024.0),
                         end_time - start_time,
                         speed)

        connection.close()
        return filename

    def get_workflow(self, workflow_name):
        """
        Get a single workflow from ReqMgr2
        """
        workflow_string = self.get('/reqmgr2/data/request?name=%s' % (workflow_name))
        if not workflow_string:
            return None

        try:
            workflow = json.loads(workflow_string)
            # 'result' is a list of elements and each of them is
            # dictionary that has workflow name as key
            return workflow.get('result', [{}])[0].get(workflow_name)
        except ValueError as ex:
            logging.error('Failed to parse workflow %s JSON %s. %s',
                          workflow_name,
                          workflow_string,
                          ex)
            return None
