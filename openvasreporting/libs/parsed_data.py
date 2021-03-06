# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

"""This file contains data structures"""

import re
from difflib import SequenceMatcher

# DEBUG
import sys
import logging

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG,
                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")



# Port object modifed to include result data field
class Port(object):
    """Port information"""

    def __init__(self, number, protocol="tcp", result=""):
        """
        :param number: port number
        :type number: int

        :param protocol: port protocol (tcp, udp, ...)
        :type protocol: basestring

	    :param result: port result
	    :type result: str

        :raises: TypeError, ValueError
        """
        if not isinstance(number, int):
            raise TypeError("Expected int, got '{}' instead".format(type(number)))
        else:
            if number < 0:
                raise ValueError("Port number must be greater than 0")

        if not isinstance(protocol, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(protocol)))

        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))

        self.number = number
        self.protocol = protocol
        self.result = result

    # Modified to include result in structure
    @staticmethod
    def string2port(info, result):
        """
        Extract port number, protocol and description from an string.
	    return a port class with seperate port, protocol and result

        ..note:
            Raises value error if information can't be processed.

        # >>> p=Port.string2port("2000/tcp","result string")
        # >>> print p.number
          2000
        # >>> print p.proto
          "tcp"
	    # >>> print p.result
	    "result string"

        # >>> p=Port.string2port("general/icmp", "string test")
        # >>> print p.number
          0
        # >>> print p.proto
          "icmp"
	    # >>> print p.result
	     "string test"

        :param info: raw string with port information
        :type info: basestring

        :param result: raw string with port information
        :type result: basestring

        :return: Port instance
        :rtype: Port

        :raises: ValueError
        """
        if not isinstance(info, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(info)))

        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))

        regex_nr = re.search("([\d]+)(/)([\w]+)", info)
        regex_general = re.search("(general)(/)([\w]+)", info)

        if regex_nr and len(regex_nr.groups()) == 3:
            number = int(regex_nr.group(1))
            protocol = regex_nr.group(3)
        elif regex_general and len(regex_general.groups()) == 3:
            number = 0
            protocol = regex_general.group(3)
        else:
            raise ValueError("Can't parse port input string")

        return Port(number, protocol, result)

    def __eq__(self, other):
        return (
                isinstance(other, Port) and
                other.number == self.number and
                other.protocol == self.protocol and
                other.result == self.result
        )


class Host(object):
    """Host information"""

    def __init__(self, ip, host_name=""):
        """
        :param ip: Host IP
        :type ip: basestring

        :param host_name: Host name
        :type host_name: basestring

        :raises: TypeError
        """
        if not isinstance(ip, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(ip)))
        #        if not isinstance(host_name, str):
        #            raise TypeError("Expected basestring, got '{}' instead".format(type(host_name)))

        self.ip = ip
        self.host_name = host_name

        # Hosts
        self.vulns = []
        self.affected = []

    # Add vuln to host like in Vulnerability just the other way around
    # Edit like there can appear multiple Vulns like in "add_vuln_host"
    def add_host_vuln(self, vuln_id, name, threat, **kwargs):
        """
        Add a host and a port associated to this vulnerability

        :param vuln_id: OpenVAS plugin id
        :type vuln_id: basestring

        :param name: Vulnerability name
        :type name: str

        :param threat: Threat type: None, Low, Medium, High
        :type threat: str

        :param cves: list of CVEs
        :type cves: list(str)

        :param certs: list of CERTs
        :type certs: list(str)

        :param cvss: CVSS number value
        :type cvss: float

        :param level: Threat level according to CVSS: None, Low, Medium, High, Critical
        :type level: str

        :param tags: vulnerability tags
        :type tags: dict

        :param references: list of references
        :type references: list(str)

        :param family: Vulnerability family
        :type family: str

        :param result: Vulnerability result
        :type result: str

        :param qod: Quality of Detection
        :type qod: int

        :param port: Port
        :type port: int

        :raises: TypeError
        """
        # Get info
        cves = kwargs.get("cves", list()) or list()
        certs = kwargs.get("certs", list()) or list()
        cvss = kwargs.get("cvss", -1.0) or -1.0
        level = kwargs.get("level", "None") or "None"
        tags = kwargs.get("tags", dict()) or dict()
        references = kwargs.get("references", list()) or list()
        family = kwargs.get("family", "Unknown") or "Unknown"
        result = kwargs.get("result", "Unknown") or "Unknown"
        port = kwargs.get("port", 0) or 0
        qod = kwargs.get("qod", 0) or 0

        if not isinstance(vuln_id, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(vuln_id)))
        if not isinstance(name, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(name)))
        if not isinstance(threat, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(threat)))
        if not isinstance(family, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(family)))
        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))
        if not isinstance(cves, list):
            raise TypeError("Expected list, got '{}' instead".format(type(cves)))
        else:
            for x in cves:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        if not isinstance(cvss, (float, int)):
            raise TypeError("Expected float, got '{}' instead".format(type(cvss)))
        if not isinstance(level, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(level)))
        if not isinstance(tags, dict):
            raise TypeError("Expected dict, got '{}' instead".format(type(tags)))
        if not isinstance(references, list):
            raise TypeError("Expected list, got '{}' instead".format(type(references)))
        else:
            for x in references:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        impact = tags.get('impact', '')
        solution = tags.get('solution', '')
        solution_type = tags.get('solution_type', '')
        insight = tags.get('insight', '')
        summary = tags.get('summary', '')
        affected = tags.get('affected', '')
        vuldetect = tags.get('vuldetect', '')

        alreadyExists = bool(False)
        for i in self.vulns:
            if i[0] == vuln_id:
                alreadyExists = bool(True)

        if alreadyExists != bool(True):
            self.vulns.append((vuln_id, name, threat, tags, cvss,
                               cves, references, family,
                               level, result, impact, solution, solution_type, insight, summary, affected, vuldetect,
                               certs, port, qod))

        # Add vuln to host like in Vulnerability just the other way around
        # Edit like there can appear multiple Vulns like in "add_vuln_host"

    def add_host_affected(self, affected, **kwargs):
        """
        Add a host and a port associated to this vulnerability
        :param affected: Affected Version description
        :type affected: str

        :param solution: Solution description
        :type solution: str

        :param cves: list of CVEs
        :type cves: list(str)

        :param certs: list of CERTs
        :type certs: list(str)

        :param qod: Quality of Detection
        :type qod: int

        :param cvss: CVSS number value
        :type cvss: float

        :param level: Threat level according to CVSS: None, Low, Medium, High, Critical
        :type level: str

        :param tags: vulnerability tags
        :type tags: dict

        """
        # Get info
        # cves = kwargs.get("cves", list()) or list()
        # certs = kwargs.get("certs", list()) or list()
        # cvss = kwargs.get("cvss", -1.0) or -1.0
        solution = kwargs.get("solution", "None") or "None"
        level = kwargs.get("level", "None") or "None"
        # tags = kwargs.get("tags", dict()) or dict()
        # references = kwargs.get("references", list()) or list()
        # family = kwargs.get("family", "Unknown") or "Unknown"
        # result = kwargs.get("result", "Unknown") or "Unknown"
        # port = kwargs.get("port", 0) or 0
        qod = kwargs.get("qod", 0) or 0

        if not isinstance(solution, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(solution)))
        if not isinstance(level, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(level)))
        # if not isinstance(name, str):
        #    raise TypeError("Expected basestring, got '{}' instead".format(type(name)))
        # if not isinstance(threat, str):
        #    raise TypeError("Expected basestring, got '{}' instead".format(type(threat)))
        # if not isinstance(family, str):
        #    raise TypeError("Expected basestring, got '{}' instead".format(type(family)))
        # if not isinstance(result, str):
        #    raise TypeError("Expected basestring, got '{}' instead".format(type(result)))
        # if not isinstance(cves, list):
        #    raise TypeError("Expected list, got '{}' instead".format(type(cves)))
        # else:
        #    for x in cves:
        #        if not isinstance(x, str):
        #            raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        # if not isinstance(cvss, (float, int)):
        #    raise TypeError("Expected float, got '{}' instead".format(type(cvss)))
        # if not isinstance(level, str):
        #    raise TypeError("Expected basestring, got '{}' instead".format(type(level)))
        # if not isinstance(tags, dict):
        #    raise TypeError("Expected dict, got '{}' instead".format(type(tags)))
        # if not isinstance(references, list):
        #    raise TypeError("Expected list, got '{}' instead".format(type(references)))
        # else:
        #    for x in references:
        #        if not isinstance(x, str):
        #            raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        # impact = tags.get('impact', '')
        # solution = tags.get('solution', '')
        # solution_type = tags.get('solution_type', '')
        # insight = tags.get('insight', '')
        # summary = tags.get('summary', '')
        # affected = tags.get('affected', '')
        # vuldetect = tags.get('vuldetect', '')

        counter = 1
        alreadyExists = bool(False)

        for k, i in enumerate(self.affected):
            if 0.7 < (similar(i[0], affected)):
#                logging.debug("######")
 #               logging.debug(i[0])
  #              logging.debug(affected)
   #             logging.debug(similar(i[0], affected))
    #            logging.debug("######")
                temp_i = list(i)
                temp_i[3] = temp_i[3] + 1
                if convert_level(temp_i[2]) < convert_level(self.affected[k][2]):
                    temp_i[2] = self.affected[k][2]
                self.affected[k] = tuple(temp_i)
                alreadyExists = bool(True)

        if alreadyExists != bool(True):
            self.affected.append((affected, solution, level, counter, qod))

    def __eq__(self, other):
        return (
                other.ip == self.ip
        )





class Vulnerability(object):
    """Vulnerability information"""

    def __init__(self, vuln_id, name, threat, **kwargs):
        """
        :param vuln_id: OpenVAS plugin id
        :type vuln_id: basestring

        :param name: Vulnerability name
        :type name: str

        :param threat: Threat type: None, Low, Medium, High
        :type threat: str

        :param cves: list of CVEs
        :type cves: list(str)

        :param cvss: CVSS number value
        :type cvss: float

        :param level: Threat level according to CVSS: None, Low, Medium, High, Critical
        :type level: str

        :param tags: vulnerability tags
        :type tags: dict

        :param references: list of references
        :type references: list(str)

        :param family: Vulnerability family
        :type family: str

        :param result: Vulnerability result
        :type description: str

        :raises: TypeError, ValueError
        """
        # Get info
        cves = kwargs.get("cves", list()) or list()
        cvss = kwargs.get("cvss", -1.0) or -1.0
        level = kwargs.get("level", "None") or "None"
        tags = kwargs.get("tags", dict()) or dict()
        references = kwargs.get("references", list()) or list()
        family = kwargs.get("family", "Unknown") or "Unknown"
        result = kwargs.get("description", "Unknown") or "Unknown"

        if not isinstance(vuln_id, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(vuln_id)))
        if not isinstance(name, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(name)))
        if not isinstance(threat, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(threat)))
        if not isinstance(family, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(family)))
        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))
        if not isinstance(cves, list):
            raise TypeError("Expected list, got '{}' instead".format(type(cves)))
        else:
            for x in cves:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        if not isinstance(cvss, (float, int)):
            raise TypeError("Expected float, got '{}' instead".format(type(cvss)))
        if not isinstance(level, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(level)))
        if not isinstance(tags, dict):
            raise TypeError("Expected dict, got '{}' instead".format(type(tags)))
        if not isinstance(references, list):
            raise TypeError("Expected string, got '{}' instead".format(type(references)))
        else:
            for x in references:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        self.vuln_id = vuln_id
        self.name = name
        self.cves = cves
        self.cvss = float(cvss)
        self.level = level
        self.description = tags.get('summary', '')
        self.detect = tags.get('vuldetect', '')
        self.insight = tags.get('insight', '')
        self.impact = tags.get('impact', '')
        self.affected = tags.get('affected', '')
        self.solution = tags.get('solution', '')
        self.solution_type = tags.get('solution_type', '')
        self.references = references
        self.threat = threat
        self.family = family
        self.result = result

        # Hosts
        self.hosts = []

    def add_vuln_host(self, host, port):
        """
        Add a host and a port associated to this vulnerability

        :param host: Host instance
        :type host: Host

        :param port: Port instance
        :type port: Port

        :raises: TypeError
        """
        if not isinstance(host, Host):
            raise TypeError("Expected Host, got '{}' instead".format(type(host)))
        if port is not None:
            if not isinstance(port, Port):
                raise TypeError("Expected Port, got '{}' instead".format(type(port)))

        if (host, port) not in self.hosts:
            self.hosts.append((host, port))

    def __eq__(self, other):
        if not isinstance(other, Vulnerability):
            raise TypeError("Expected Vulnerability, got '{}' instead".format(type(other)))

        if (
                other.vuln_id != self.vuln_id or
                other.name != self.name or
                other.cves != self.cves or
                other.cvss != self.cvss or
                other.level != self.level or
                other.description != self.description or
                other.detect != self.detect or
                other.insight != self.insight or
                other.impact != self.impact or
                other.affected != self.affected or
                other.solution != self.solution or
                other.solution_type != self.solution_type or
                other.references != self.references or
                other.threat != self.threat or
                other.family != self.family or
                other.result != self.result
        ):
            return False

        for host, port in self.hosts:
            for o_host, o_port in other.hosts:
                if o_host != host or o_port != port:
                    return False

        return True


def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

def convert_level(level):
    if level == 'critical':
        return 5
    elif level == 'high':
        return 4
    elif level == 'medium':
        return 3
    elif level == 'low':
        return 2
    elif level == 'None':
        return 1
    else:
        return 0


def backconvert_level(level):
    if level == 5:
        return 'critical'
    elif level == 4:
        return 'high'
    elif level == 3:
        return 'medium'
    elif level == 2:
        return 'low'
    elif level == 1:
        return 'None'
    else:
        return 'None'



