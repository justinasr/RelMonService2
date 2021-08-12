"""
Module that contains Database class
"""
import logging
import time
import json
import os
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError


class Database:
    """
    Database class represents MongoDB database
    It encapsulates underlying connection and exposes some convenience methods
    """
    PAGE_SIZE = 10
    DATABASE_HOST = 'localhost'
    DATABASE_PORT = 27017
    DATABASE_NAME = 'relmons'
    COLLECTION_NAME = 'relmons'
    USERNAME = None
    PASSWORD = None

    def __init__(self):
        self.logger = logging.getLogger('logger')
        db_host = os.environ.get('DB_HOST', Database.DATABASE_HOST)
        db_port = os.environ.get('DB_PORT', Database.DATABASE_PORT)
        if Database.USERNAME and Database.PASSWORD:
            self.logger.debug('Using DB with username and password')
            self.client = MongoClient(db_host,
                                      db_port,
                                      username=Database.USERNAME,
                                      password=Database.PASSWORD,
                                      authSource='admin',
                                      authMechanism='SCRAM-SHA-256')[Database.DATABASE_NAME]
        else:
            self.logger.debug('Using DB without username and password')
            self.client = MongoClient(db_host, db_port)[Database.DATABASE_NAME]

        self.relmons = self.client[self.COLLECTION_NAME]

    @classmethod
    def set_credentials(cls, username, password):
        """
        Set database username and password
        """
        cls.USERNAME = username
        cls.PASSWORD = password

    @classmethod
    def set_credentials_file(cls, filename):
        """
        Load credentials from a JSON file
        """
        with open(filename) as json_file:
            credentials = json.load(json_file)

        cls.set_credentials(credentials['username'], credentials['password'])

    def create_relmon(self, relmon):
        """
        Add given RelMon to the database
        """
        relmon_json = relmon.get_json()
        relmon_json['last_update'] = int(time.time())
        relmon_json['_id'] = relmon_json['id']
        try:
            return self.relmons.insert_one(relmon_json)
        except DuplicateKeyError:
            return None

    def update_relmon(self, relmon):
        """
        Update given RelMon in the database based on ID
        """
        relmon_json = relmon.get_json()
        relmon_json['last_update'] = int(time.time())
        if '_id' not in relmon_json:
            self.logger.error('No _id in document')
            return

        try:
            self.relmons.replace_one({'_id': relmon_json['_id']}, relmon_json)
        except DuplicateKeyError:
            return

    def delete_relmon(self, relmon):
        """
        Delete given RelMon from the database based on it's ID
        """
        self.relmons.delete_one({'_id': relmon.get_id()})

    def get_relmon_count(self):
        """
        Return total number of RelMons in the database
        """
        return self.relmons.count_documents({})

    def get_relmon(self, relmon_id):
        """
        Fetch a RelMon with given ID from the database
        """
        return self.relmons.find_one({'_id': relmon_id})

    def get_relmons(self, query_dict=None, page=0, page_size=PAGE_SIZE):
        """
        Search for relmons in the database
        Return list of paginated RelMons and total number of search results
        """
        if query_dict is None:
            query_dict = {}

        relmons = self.relmons.find(query_dict).sort('_id', -1)
        total_rows = relmons.count()
        relmons = relmons.skip(page * page_size).limit(page_size)
        return list(relmons), total_rows

    def get_relmons_with_status(self, status):
        """
        Get list of RelMons with given status
        """
        relmons = self.relmons.find({'status': status})
        return list(relmons)

    def get_relmons_with_condor_status(self, status):
        """
        Get list of RelMons with given HTCondor status
        """
        relmons = self.relmons.find({'condor_status': status})
        return list(relmons)

    def get_relmons_with_name(self, relmon_name):
        """
        Get list of (should be one) RelMons with given name
        """
        relmons = self.relmons.find({'name': relmon_name})
        return list(relmons)
