#!/usr/bin/env python

import sys
import argparse
import requests
from NagiosResponse import NagiosResponse
import json

TIMEOUT = 180


class AgoraHealthCheck:

    RESOURCES_PATH = '/api/v2/resources/'
    LOGIN_PATH = '/api/v2/auth/login/'
    HEADERS = {'Content-type': 'application/json'}


    def __init__(self, args=sys.argv[1:]):
        self.args = parse_arguments(args)
        self.verify_ssl = not self.args.ignore_ssl
        self.nagios = NagiosResponse("Agora is up.")
        self.token = ""

    def check_endpoint(self, endpointExtension='', checkJSON=False):
        try:
            endpoint = self.args.url + endpointExtension
            r = requests.get(endpoint, verify=self.verify_ssl,
                             timeout=self.args.timeout)
            r.raise_for_status()
            if checkJSON and not len(r.json()):
                self.nagios.writeCriticalMessage("No services found at " + endpoint)
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code
            self.nagios.writeCriticalMessage("Invalid response code: " + str(code))
        except requests.exceptions.SSLError as e:
            self.nagios.writeCriticalMessage("SSL Error")
        except requests.exceptions.RequestException as e:
            self.nagios.writeCriticalMessage("Cannot connect to endpoint " + endpoint)
        except ValueError:
            self.nagios.writeCriticalMessage("Malformed JSON at " + endpoint)

    def login(self):
        payload = {
                    'username': self.args.username,
                    'password': self.args.password,
        }

        login_url = 'https://{0}/{1}'.format(self.args.url, self.LOGIN_PATH)
        
        login_resp = requests.post(url=login_url, data=json.dumps(payload), headers=self.HEADERS, verify=self.args.ignore_ssl, timeout=self.args.timeout)

        if login_resp.status_code != 200:
            if self.args.verbose:
                self.nagios.writeCriticalMessage("Cannot login.{0}.".format(login_resp.text))
            else:
                self.nagios.writeCriticalMessage("Cannot login.")
            return

        if "auth_token" not in login_resp.json():
            if self.args.verbose:
                self.nagios.writeCriticalMessage("Could not retrieve auth_token.{0}.".format(login_resp.text))
            else:
                self.nagios.writeCriticalMessage("Could not retrieve auth_token.")
            return

        self.token = login_resp.json()["auth_token"]


    def check_resources(self):
        self.HEADERS['Authorization'] = 'Token {}'.format(self.token)
        resources_url = 'https://{0}/{1}'.format(self.args.url, self.RESOURCES_PATH)

        resources_resp = requests.get(url=resources_url, headers=self.HEADERS, verify=self.args.ignore_ssl, timeout=self.args.timeout)

        if resources_resp.status_code != 200:
            if self.args.verbose:
                self.nagios.writeCriticalMessage("Could not retrieve resources.{0}.".format(resources_resp.text))
            else:
                self.nagios.writeCriticalMessage("Could not retrieve resources.")

        if len(resources_resp.json()) == 0:
            if self.args.verbose:
                self.nagios.writeWarningMessage("No resources available.{0}.".format(resources_resp.text))
            else:
                self.nagios.writeWarningMessage("No resources available.")
            return

    def run(self):
        try:
            self.login()
            self.check_resources()
        except requests.exceptions.SSLError as ssle:
            self.nagios.writeCriticalMessage("SSL Error.{0}.".format(str(ssle)))
        except requests.exceptions.ConnectionError as ce:
            self.nagios.writeCriticalMessage("Connecton Error.{0}.".format(str(ce)))
        
        self.nagios.printAndExit()


def parse_arguments(args):
    parser = argparse.ArgumentParser(description="Nagios Probe for Agora")
    parser.add_argument('-U', '--url', dest='url', required=True,
                        type=str, help='Agora\'s url')
    parser.add_argument('-v', '--verbose', dest='verbose',
                        action='store_true', help='verbose output')
    parser.add_argument('-t', '--timeout', dest='timeout', type=int,
                        default=TIMEOUT,
                        help='timeout for requests, default=' + str(TIMEOUT))
    parser.add_argument('-u', '--username', dest='username', type=str,
                        help='username')
    parser.add_argument('-p', '--password', dest='password', type=str,
                        help='password')
    parser.add_argument('-i', '--insecure', dest='ignore_ssl',
                        action='store_true', default=False,
                        help='ignore SSL errors')
    return parser.parse_args(args)


if __name__ == "__main__":
    check = AgoraHealthCheck()
    check.run()