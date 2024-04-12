# interact with Validin API
# {dmitry.chan|john.lampe}@gmail.com

import requests
import logging
import pdb


class Validin:
    def __init__(self, api_key=None, verify=True):
        if api_key:
            self.api_key = api_key
            self.verify = verify
        else:
            logging.error("Need an API key. Edit validin.yml and add. Program exiting")
            print("Need an API key. Edit validin.yml and add. Program exiting")
            exit(0)

        self.base_url = "https://app.validin.com/api/axon/"

        self.session = requests.Session()
        self.session.verify = self.verify
        self.session.headers = {"Accept": "*/*",
                                "Authorization": "Bearer {}".format(self.api_key)}

    def get(self, *args, **kwargs):
        """
        Sends an HTTP GET request to the uri (*args)
        :param args: URI
        :param kwargs: options to the GET request
        :return: string
        """
        ret = self.session.get(*args, **kwargs)
        if ret.status_code == 200:
            return ret.json()
        else:
            return {'Error' : "Received a non-200 response when requesting domain : {}. Status Code: {}".format(*args, ret.status_code)}


    def domain_history_a_aaaa_ns(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDNSHistory
        Retrieve A, AAAA, and NS records
        :param domain: required string
        :param limit: optional, integer must be between 1-1000
        :param wildcard: optional Boolean
        :param first_seen: optional, string, format YYYY-MM-DD
        :param last_seen: optional, string, format YYYY-MM-DD
        :return: JSON
        """

        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/dns/history/{}".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_a(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDNSHistoryA
        Retrieve A records
        :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/dns/history/{}/A".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_aaaa(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDNSHistoryAAAA
        Retrieve AAAA records
        :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/dns/history/{}/AAAA".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_ns(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDNSHistoryNS
        Retrieve NS records
        :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/dns/history/{}/NS".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_ns_for(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDNSHistoryNS_FOR
        Retrieve NS records
        :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/dns/history/{}/NS_FOR".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_ptr(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDomainPTR
        Retrieve PTR records
        :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/dns/hostname/{}".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_osint(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDomainOsintHistory
        Retrieve OSINT analysis
         :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/osint/history/{}".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_osint_context(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDomainOsintContext
        Retrieve OSINT context analysis
         :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error' : "No domain specified"}
        else:
            uri = "{}domain/osint/context/{}".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def domain_pivots(self, domain=None, **kwargs):
        """
        https://app.validin.com/docs/getDomainPivots
        Retrieve OSINT context analysis
        :param domain: required string
        :param kwargs: optional GET params to pass to query
        :return: JSON
        """
        if not domain:
            return {'Error': "No domain specified"}
        else:
            uri = "{}domain/pivots/{}".format(self.base_url, domain)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_history(self, ip=None, **kwargs):
        """
        https://app.validin.com/docs/getIP_DNSHistory
        :param ip: string IP address
        :param kwargs: optional GET params to pass to query
        :return:
        """
        if not ip:
            return {'Error': "No IP specified"}
        else:
            uri = "{}ip/dns/history/{}".format(self.base_url, ip)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_cidr(self, ip=None, cidr=None, **kwargs):
        """
        https://app.validin.com/docs/getCIDR_DNSHistory
        %20/api/axon/ip/dns/history/:ip/:cidr
        :param ip: string IP
        :param kwargs: optional GET params
        :return: JSON
        """
        if not ip or not cidr:
            return {'Error': "No IP and/or CIDR specified"}
        else:
            uri = "{}ip/dns/history/{}/{}".format(self.base_url, ip, cidr)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_ptr(self, ip=None, **kwargs):
        """
        https://app.validin.com/docs/getIpPTR
        /api/axon/ip/dns/hostname/:ip
        :param ip: string IP
        :param kwargs: optional GET params
        :return: JSON
        """
        if not ip:
            return {'Error': "No IP specified"}
        else:
            uri = "{}ip/dns/hostname/{}".format(self.base_url, ip)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_ptr_cidr(self, ip=None, cidr=None, **kwargs):
        """
        https://app.validin.com/docs/getCidrPTR
        :param ip: string IP
        :param cidr: integer
        :return: JSON
        """
        if not ip or not cidr:
            return {'Error': "No IP and/or CIDR specified"}
        else:
            uri = "{}ip/dns/hostname/{}/{}".format(self.base_url, ip, cidr)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_osint(self, ip=None, **kwargs):
        """
        https://app.validin.com/docs/getIPOsintHistory
        /api/axon/ip/osint/history/:ip
        :param ip: string IP
        :param kwargs: optional GET params
        :return: JSON
        """
        if not ip:
            return {'Error': "No IP specified"}
        else:
            uri = "{}ip/osint/history/{}".format(self.base_url, ip)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_osint_cidr(self, ip=None, cidr=None, **kwargs):
        """
        /api/axon/ip/osint/history/:ip/:cidr
        https://app.validin.com/docs/getCidrOsintHistory
        :param ip: string IP
        :param cidr: integer
        :return: JSON
        """
        if not ip or not cidr:
            return {'Error': "No IP and/or CIDR specified"}
        else:
            uri = "{}ip/osint/history/{}/{}".format(self.base_url, ip, cidr)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_osint_context(self, ip=None, **kwargs):
        """
        https://app.validin.com/docs/getIpOsintContext
        :param ip: string IP
        :param kwargs: optional GET params
        :return: JSON
        """
        if not ip:
            return {'Error': "No IP specified"}
        else:
            uri = "{}ip/osint/context/{}".format(self.base_url, ip)

        ret = self.get(uri, **kwargs)
        return ret

    def ip_pivots(self, ip=None, **kwargs):
        """
        /api/axon/ip/pivots/:ip
        https://app.validin.com/docs/getIPPivots
        :param ip: string IP
        :param kwargs: optional GET params
        :return: JSON
        """
        if not ip:
            return {'Error': "No IP specified"}
        else:
            uri = "{}ip/pivots/{}".format(self.base_url, ip)

        ret = self.get(uri, **kwargs)
        return ret

    def ping(self, **kwargs):
        """
        https://app.validin.com/docs/ping
        :param kwargs:  optional GET params
        :return: JSON
        """
        uri = "https://app.validin.com/api/ping"

        ret = self.get(uri, **kwargs)
        return ret

