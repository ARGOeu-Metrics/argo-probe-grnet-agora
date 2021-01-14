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

    def login(self):
        payload = {
                    'username': self.args.username,
                    'password': self.args.password,
        }

        login_url = 'https://{0}/{1}'.format(self.args.hostname, self.LOGIN_PATH)
        
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
        resources_url = 'https://{0}/{1}'.format(self.args.hostname, self.RESOURCES_PATH)

        resources_resp = requests.get(url=resources_url, headers=self.HEADERS, verify=self.args.ignore_ssl, timeout=self.args.timeout)

        if resources_resp.status_code != 200:
            if self.args.verbose:
                self.nagios.writeCriticalMessage("Could not retrieve resources.{0}.".format(resources_resp.text))
            else:
                self.nagios.writeCriticalMessage("Could not retrieve resources.")

        if self.args.listview_check:
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
    parser.add_argument('-H', '--hostname', dest='hostname', required=True,
                        type=str, help='Agora\'s hostname')
    parser.add_argument('-v', '--verbose', dest='verbose',
                        action='store_true', help='verbose output')
    parser.add_argument('-l', '--listview', dest='listview_check',
                        default=False, action='store_true',
                        help='check if the listViews have records')
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
