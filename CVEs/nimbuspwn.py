"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from Modules import os_type, commons, os_release, constants, receive_package

CVE_ID = 'NIMBUSPWN'
DESCRIPTION = f'''{CVE_ID} - CVE-2022-29799, CVE-2022-29800

CVSS Score: N/A
NVD Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29799

CVSS Score: N/A
NVD Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29800

Your system will be scanned for all NIMBUSPWN related CVEs. 
The vulnerabilities are collectively dubbed as Nimbuspwn and have been identified as CVE-2022-29799 and CVE-2022-29800.
Exploiting Nimbuspwn vulnerabilities together, can be chained to gain root privileges on Linux systems, allowing 
attackers to deploy payloads, like a root backdoor, and perform other malicious actions via arbitrary root code 
execution. 
The CVE-2022-29799 is a path traversal vulnerability as a result of a missing check in the networkd-dispatcher component
implementation. The attacker can move between folders in the file system.
The CVE-2022-29800 is a TOCTOU (Time of Check - Time of Use) race vulnerability, caused by validation checks the 
networkd-dispatcher performs in order to validate which scripts in the checked directory have root permissions. 
If a large amount of scripts need to be validated, the checks take time and meanwhile, the attacker can replace the 
subdirectory and cause malicious scripts to be executed instead.
'''
AFFECTED_VERSIONS = {'Debian 10': '2.0-2', 'Debian 11': '2.1-2', 'Debian 12': '2.1-2', 'Debian unstable': '2.1-2',
                     'Ubuntu 18.04': '1.7-0ubuntu3.4', 'Ubuntu 20.04': '2.1-2~ubuntu20.04.2',
                     'Ubuntu 21.10': '2.1-2ubuntu0.21.10.1', 'Ubuntu 22.04': '2.1-2ubuntu0.22.04.1'}


def check_networkd_version(host_information, debug, container_name):
    """This function checks if the networkd-dispatcher version is affected."""
    affected = False
    distribution = host_information.split(' ')[constants.START]
    package_name = 'networkd-dispatcher'
    host_network_version = receive_package.package_version_apt(distribution, package_name, debug, container_name)
    if host_network_version:
        print(constants.FULL_QUESTION_MESSAGE.format('Is networkd-dispatcher policy version affected?'))
        affected_networkd_version = AFFECTED_VERSIONS[host_information]
        if version.parse(host_network_version) > version.parse(affected_networkd_version):
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your version which is: {host_network_version}, is higher '
                                                            f'than the last affected version which is: '
                                                            f'{affected_networkd_version}'))
        elif version.parse(host_network_version) == version.parse(affected_networkd_version):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your version which is: {host_network_version}, is '
                                                            f'affected'))
            affected = True
        else:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your version which is: {host_network_version}, is lower '
                                                            f'than the last affected version which is: '
                                                            f'{affected_networkd_version}'))
            affected = True
    return affected


def distribution_version_affected(debug, container_name):
    """This function checks if the host distribution and version are affected."""
    information_fields = ['Distribution', 'Version']
    host_information = os_release.get_field(information_fields, debug, container_name)
    print(constants.FULL_QUESTION_MESSAGE.format('Is os release affected?'))
    if host_information == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    if not host_information:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no distribution and '
                                                        'version values'))
        return constants.UNSUPPORTED
    if host_information in AFFECTED_VERSIONS:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os releases: {list(AFFECTED_VERSIONS.keys())}\n'
                                                        f'Your os release: {host_information}\nThe os release you '
                                                        f'are running on is potentially affected'))
        return host_information
    if host_information.split(' ')[constants.START] in constants.APT_DISTRIBUTIONS:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your os distribution and version which is: '
                                                        f'{host_information}\nAffected distributions and versions: '
                                                        f'{list(AFFECTED_VERSIONS.keys())}\nYour distribution and '
                                                        f'version are not affected'))
        return ''
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os distributions: Ubuntu and Debian\nYour os '
                                                    f'distribution: {host_information}\nThe os distribution you'
                                                    f' are running on is not affected'))
    return ''


def validate(debug, container_name):
    """This function validates if an instance is vulnerable to NIMBUSPWN."""
    if os_type.linux(debug, container_name):
        host_information = distribution_version_affected(debug, container_name)
        if host_information:
            if check_networkd_version(host_information, debug, container_name):
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
    else:
        print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of NIMBUSPWN."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Are os distribution and version affected?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are os distribution and version affected?', 'Is networkd-dispatcher policy version affected?',
                   label='Yes')
    vol_graph.edge('Are os distribution and version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is networkd-dispatcher policy version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is networkd-dispatcher policy version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
