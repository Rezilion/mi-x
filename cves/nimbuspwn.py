"""
Support for version from packaging and other modules written to avoid repetitive code.
"""
from packaging import version
from modules import constants, graph_functions, status, os_release, receive_package

VULNERABILITY = 'NIMBUSPWN'
DESCRIPTION = f'''{VULNERABILITY} - CVE-2022-29799, CVE-2022-29800

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

Related Links:
https://www.rezilion.com/blog/nimbuspwn-what-you-need-to-know-now/
https://thesecmaster.com/how-to-fix-nimbuspwn-vulnerability-in-linux-a-privilege-escalation-vulnerability-in-networkd-dispatcher/
https://www.esecurityplanet.com/threats/nimbuspwn-root-privilege-escalation-linux/
https://www.microsoft.com/security/blog/2022/04/26/microsoft-finds-new-elevation-of-privilege-linux-vulnerability-nimbuspwn/
'''
CVE_1 = 'NIMBUSPWN - CVE-2022-29799'
CVE_2 = 'NIMBUSPWN - CVE-2022-29799 and CVE-2022-29800'
AFFECTED_CVE_1 = {'Debian 10': '2.0-2', 'Debian 11': '2.1-2', 'Debian 12': '2.1-2', 'Debian unstable': '2.1-2',
                  'Ubuntu 18.04': '1.7-0ubuntu3.4', 'Ubuntu 20.04': '2.1-2~ubuntu20.04.2',
                  'Ubuntu 21.10': '2.1-2ubuntu0.21.10.1', 'Ubuntu 22.04': '2.1-2ubuntu0.22.04.1'}
AFFECTED_CVE_2 = {'Debian 10': '2.0-2', 'Debian 11': '2.1-2', 'Debian 12': '2.1-2', 'Debian unstable': '2.1-2',
                  'Ubuntu 18.04': '1.7-0ubuntu3.3', 'Ubuntu 20.04': '2.1-2~ubuntu20.04.1',
                  'Ubuntu 21.10': '2.1-2ubuntu0.21.10.0', 'Ubuntu 22.04': '2.1-2ubuntu0.22.04.0'}
AFFECTED_DISTRIBUTIONS = ['Debian 10', 'Debian 11', 'Debian 12', 'Debian unstable', 'Ubuntu 18.04', 'Ubuntu 20.04',
                          'Ubuntu 21.10', 'Ubuntu 22.04']
FIXED = {'Ubuntu 18.04': '1.7-0ubuntu3.5', 'Ubuntu 20.04': '2.1-2~ubuntu20.04.3',
         'Ubuntu 21.10': '2.1-2ubuntu0.21.10.2', 'Ubuntu 22.04': '2.1-2ubuntu0.22.04.2'}
REMEDIATION = f'Upgrade Ubuntu `networkd-dispatcher` version to:\n{FIXED}'
MITIGATION = 'Remove the networkd-dispatcher by using one of the following commands:\nsudo apt-get remove ' \
             'networkd-dispatcher\nsudo systemctl stop systemd-networkd.service\nsudo systemctl disable ' \
             'systemd-networkd.service'


def print_not_affected(host_network_version, affected_networkd_version):
    """This function prints out the not affected message."""
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your version which is: {host_network_version}, is higher than or '
                                                    f'equals to the patched version which is: '
                                                    f'{affected_networkd_version}'))


def print_affected(host_network_version, affected_networkd_version):
    """This function prints out the affected message."""
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your version which is: {host_network_version}, is lower that the '
                                                    f'patched version which is: {affected_networkd_version}'))


def compare_versions(affected_networkd_version, host_network_version):
    """This function compares the networkd-dispatcher version between the founded version on host and the maximum
    affected version."""
    affected = False
    if version.parse(host_network_version) <= version.parse(affected_networkd_version):
        affected = True
    return affected


def check_networkd_version(host_information, debug, container_name):
    """This function checks if the networkd-dispatcher version is affected."""
    vulnerability = ''
    distribution = host_information.split(' ')[constants.START]
    package_name = 'networkd-dispatcher'
    host_network_version = receive_package.package_version_apt(distribution, package_name, debug, container_name)
    if host_network_version:
        print(constants.FULL_QUESTION_MESSAGE.format('Is networkd-dispatcher policy version affected?'))
        affected_versions = AFFECTED_CVE_2
        affected_networkd_version_1 = affected_versions[host_information]
        affected = compare_versions(host_information, host_network_version)
        if affected:
            print_affected(host_network_version, affected_networkd_version_1)
            return CVE_2
        else:
            affected_versions = AFFECTED_CVE_1
            affected_networkd_version_2 = affected_versions[host_information]
            affected = compare_versions(host_information, host_network_version)
            if affected:
                print_affected(host_network_version, affected_networkd_version_2)
                return CVE_1
            else:
                print_not_affected(host_network_version, affected_networkd_version_1)
    return vulnerability


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
    if host_information in AFFECTED_DISTRIBUTIONS:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os releases: {AFFECTED_DISTRIBUTIONS}\n'
                                                        f'Your os release: {host_information}\nThe os release you '
                                                        f'are running on is potentially affected'))
        return host_information
    if host_information.split(' ')[constants.START] in constants.APT_DISTRIBUTIONS:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Your os distribution and version which are: '
                                                        f'{host_information}, are not affected'))
        return ''
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected os distributions are: Ubuntu and Debian\nYour os '
                                                    f'distribution which is: {host_information}, is not affected'))
    return ''


def validate(debug, container_name):
    """This function validates if an instance is vulnerable to NIMBUSPWN."""
    state = {}
    host_information = distribution_version_affected(debug, container_name)
    if host_information:
        vulnerability = check_networkd_version(host_information, debug, container_name)
        if vulnerability:
            state[VULNERABILITY] = status.vulnerable(vulnerability)
            status.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    else:
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of NIMBUSPWN."""
    vulnerability_graph = graph_functions.graph_start(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Are os distribution and version affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Are os distribution and version affected?', 'Is networkd-dispatcher policy version affected?',
                   label='Yes')
    vulnerability_graph.edge('Are os distribution and version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is networkd-dispatcher policy version affected?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is networkd-dispatcher policy version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
