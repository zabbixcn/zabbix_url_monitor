#!/usr/bin/python
# -*- coding: utf-8 -*-
import yaml
import logging
import packaging

class ConfigObject(object):
    """ This class makes YAML configuration
    available as python datastructure. """

    def __init__(self):
        self.config = None
        self.checks = None

    def load_yaml_file(self, config):
        if config == None:
            config ="/etc/url_monitor.yaml"

        with open(config, 'r') as stream:
            try:
                self.config = (yaml.load(stream))
                return self.config
            except yaml.YAMLError as exc:
                print(exc)

    def load(self):
        """ This is the main config load function to pull in
            configurations to convienent and common namespace. """
        return {'checks':             self._loadChecks(),
                'config':             self._loadConfig(),
                'identity_providers': self._loadConfigIdentityProviders()}

    def _loadChecks(self,withIdentityProvider=None):
        """ Loads the checks for work to be run.
            Default loads all checks, withIdentityProvider option will limit checks
            returned by identity provider (useful for smart async request grouping)  """
        loaded_checks      = []

        if withIdentityProvider:
            # Useful if doing grouping async requests with a shared identityprovider
            #  and then spawning async call
            for checkdata in self._loadTestSetList():
                if checkdata['data']['identity_provider'].lower() == withIdentityProvider.lower():
                    #loaded_checks.append({'data': checkdata['data']})
                    loaded_checks.append(checkdata)

        else:
            loaded_checks = self._loadTestSetList()

        return loaded_checks

    def _loadConfig(self):
        """ Return base config key """
        return self.config['config']

    def _loadConfigIdentityProviders(self):
        """ This fetches out a list of identity providers kwarg configs from main config """
        providers = {}
        for provider_config_alias, v in self._loadConfig()['identity_providers'].iteritems():
            # Add each provider and config to dictionary from yaml file.
            providers[provider_config_alias] = v
        # Return a list of the config 
        return providers

        """ Loads a list of the checks """

    def _uniq(self,seq):
        """ Returns a unique list when a list of
         non unique items are put in """
        set = {}
        map(set.__setitem__, seq, [])
        return set.keys()

    def getDatatypesList(self):
        """ Used by the discover command to identify a list of valid datatypes """
        possible_datatypes = []
        for testSet in self._loadChecks():
            checkname = testSet['key']
            try:
                uri = testSet['data']['uri']
            except KeyError, err:
                error = "\n\nError: Missing " + str(err) + " under testSet item "+ str(testSet['key']) +", discover cannot run.\n1"
                raise Exception("KeyError: " + str(err) + str(error))

            try:
                testSet['data']['testElements']
            except KeyError, err:
                error = "\n\nError: Missing " + str(err) + " under testSet item "+ str(testSet['key']) +", discover cannot run.\n1"
                raise Exception("KeyError: " + str(err) + str(error))

            for element in testSet['data']['testElements']:  # For every test element
                try:
                    datatypes = element['datatype'].split(',')
                except KeyError, err:
                    error = "\n\nError: Missing " + str(err) + " under testElements in "+ str(testSet['key']) +", discover cannot run.\n1"
                    raise Exception("KeyError: " + str(err) + str(error))
                for datatype in datatypes:
                    possible_datatypes.append(datatype)

        return str(self._uniq(possible_datatypes))
    def get_log_level(self,debug_level=None):
        """ Allow user-configurable log-leveling """
        try:
            if debug_level == None:
                debug_level = self.config['config']['loglevel']
        except KeyError, err:
            print("Error: Missing " + str(err) + " in config under config: loglevel.\nTry config: loglevel: Exceptions")
            print("1")
            exit(1)
        if (debug_level.lower().startswith('err') or debug_level.lower().startswith('exc')):
            return logging.ERROR
        elif debug_level.lower().startswith('crit'):
            return logging.CRITICAL
        elif debug_level.lower().startswith('warn'):
            return logging.WARNING
        elif debug_level.lower().startswith('info'):
            return logging.INFO
        elif debug_level.lower().startswith('debu'):
            return logging.DEBUG
        else:
            return logging.ERROR

    def getLogger(self,loglevel):
        """ Returns a logger instance to be used throughout. This was moved into configuration to
            get logging abilities as soon as possible in the application.
        """
        self.logger = logging.getLogger(packaging.package)
        loglevel = self.get_log_level(loglevel)
        # Setup file handle
        handler = logging.FileHandler('/var/log/url_monitor.log')
        handler.setLevel(loglevel)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        logging.basicConfig(level=loglevel)
        self.logger.info("Logger initialized.")
        return self.logger

    def preFlightCheck(self):
        """ Trys loading all the config objects for zabbix conf. This can be expanded to do
            all syntax checking in this config class, instead of in the program logic as it is
            mostly right now.

            It is a check class. This should NOT be used for program references.
            (Doesnt use logger for exceptions as it pre-dates logger instanciation.)
            """
        # Ensure base config elements exist.
        try:
            self.config['config']
        except KeyError, err:
            error = "\n\nError: Config missing zabbix: " + str(err) + " structure in config under config\n" \
            + "Ensure \n  " + str(err) + ":  is defined\n1"
            self.logger.exception("KeyError: " + str(err) + str(error))
            exit(1)

        try:
            self.config['config']['zabbix']
        except KeyError, err:
            error = "\n\nError: Config missing: " + str(err) + " structure in config under config\n" \
            + "Ensure \n  config:\n     " + str(err) + ":  is defined\n1"
            self.logger.exception("KeyError: " + str(err) + str(error))
            exit(1)

        try:
            self.config['config']['zabbix']['port']
            self.config['config']['zabbix']['host']
            self.config['config']['zabbix']['item_key_format']
        except KeyError, err:
            error = "\n\nError: Config missing: " + str(err) + " structure in config under config\n" \
            + "Ensure \n  config:\n     zabbix:\n        " + str(err) + ":  is defined\n1"
            self.logger.exception("KeyError: " + str(err) + str(error))
            exit(1)

        # Ensure identity items exist
        try:
            self.config['config']['identity_providers']
        except KeyError, err:
            error = "\n\nError: Config missing: " + str(err) + " structure in config under config\n" \
            + "Ensure \n  config:\n     " + str(err) + ":  is defined\n1"
            self.logger.exception("KeyError: " + str(err) + str(error))
            exit(1)


        try:
            for provider in self._loadConfigIdentityProviders():
                provider
        except AttributeError, err:
            error = "\n\nError: Config missing: " + str(err) + " structure in config: identity_providers\n" \
            + "Ensure \n  identity_providers follows documentation\n1"
            self.logger.exception("AttributeError: " + str(err) + str(error))
            exit(1)

        for provider in self._loadConfigIdentityProviders():
            provider
            for module, kwargs in self.config['config']['identity_providers'][provider].iteritems():
                module.split('/')
                for kwarg in kwargs:
                    kwarg


        self.logger.info("Pre-flight config test OK")

    def _loadTestSetList(self):
        """ Used to prepare format of data for the checker functions
        out of the configuration file.
        Here is a sample of return output.
        [{
            "elements": [
                {
                    "jsonvalue": "./jobSuccess",
                    "key": "StatusJob.success"
                },
                {
                    "jsonvalue": "./jobFailure",
                    "key": "StatusJob.failure"
                }
            ],
            "response_type": "json",
            "url": "https://x.net/v3/jobs/statusjob/stats/totals"
        },
        {
            "elements": [
                {
                    "jsonvalue": "./report[1]/status",
                    "key": "./report[1]/name"
                },
            ],
            "response_type": "json",
            "url": "https://x.net/dependencies"
        }]"""
        self.checks = []
        for testSet in self.config['testSet']:
            for key, v in testSet.iteritems():
                self.checks.append({'key': key, 'data': testSet[key]})

        return self.checks

if __name__ == "__main__":
    x = ConfigObject()
    x.load_yaml_file(config=None)
    a = x._loadChecks()
    print(a)
    print(x.getDatatypeList())