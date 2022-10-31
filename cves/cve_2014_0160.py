"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from modules import status, commons, constants, os_release, receive_package

VULNERABILITY = 'CVE-2014-0160'
DESCRIPTION = f'''Heartbleed

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-0160

{VULNERABILITY} is a programming mistake in a popular OpenSSL library that provides cryptographic services such as SSL/TLS to 
the applications and services.
Due to a missing/incorrect bounds check in the code, it is possible to return chunks of memory from a TLS peer (client 
or server) by sending invalid requests which are incorrectly processed.
Attackers can exploit the vulnerability and leak sensitive information such as the private key, account names and/or 
passwords.

Related Links:
https://heartbleed.com/
https://www.synopsys.com/blogs/software-security/heartbleed-vulnerability-appsec-deep-dive/
'''
AFFECTED_VERSIONS_MESSAGE = '1.0.1 up to including 1.0.1f and 1.0.2 up to including 1.0.2beta1'
AFFECTED_VERSION_START = '1.0.1'
AFFECTED_VERSION_RANGE = ['a', 'f']
AFFECTED_VERSIONS = ['1.0.2', '1.0.2beta1']
MAX_AFFECTED_VERSION = '2.17'
REMEDIATION = 'Upgrade openssl version to 1.0.1g, 1.0.2-beta2 or higher.'
MITIGATION = ''


def check_openssl_version(openssl_version):
    """This function checks if the OpenSSL version is affected."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format('Is OpenSSL version affected?'))
    if version.parse(AFFECTED_VERSION_START) == version.parse(openssl_version):
        affected = True
    elif AFFECTED_VERSION_START in openssl_version:
        before_keyword, keyword, after_keyword = openssl_version.partition(AFFECTED_VERSION_START)
        if version.parse(AFFECTED_VERSION_RANGE[constants.START]) <= version.parse(after_keyword) <= \
                version.parse(AFFECTED_VERSION_RANGE[constants.END]):
            affected = True
    for affected_version in AFFECTED_VERSIONS:
        if version.parse(affected_version) == version.parse(openssl_version):
            affected = True
    if affected:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected OpenSSL versions are: {AFFECTED_VERSIONS_MESSAGE}\n'
                                                        f'Your OpenSSL version which is: {openssl_version} is '
                                                        f'affected'))
        return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected OpenSSL versions are {AFFECTED_VERSIONS_MESSAGE}\nYour '
                                                    f'OpenSSL version which is: {openssl_version} is not affected'))
    return False


def get_openssl_version(debug, container_name):
    """This function returns the openssl version if exists."""
    information_fields = ['Distribution']
    distribution = os_release.get_field(information_fields, debug, container_name)
    package_name = 'openssl'
    if distribution in constants.APT_DISTRIBUTIONS:
        return receive_package.package_version_apt(distribution, package_name, debug, container_name)
    if distribution in constants.RPM_DISTRIBUTIONS:
        return receive_package.package_version_rpm(distribution, package_name, debug, container_name)
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Heartbleed vulnerabilities."""
    state = {}
    openssl_version = get_openssl_version(debug, container_name)
    if openssl_version == constants.UNSUPPORTED:
        state[VULNERABILITY] = status.not_determined(VULNERABILITY)
    elif openssl_version:
        if check_openssl_version(openssl_version):
            state[VULNERABILITY] = status.vulnerable(VULNERABILITY)
            status.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    else:
        state[VULNERABILITY] = status.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Heartbleed."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there openssl?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there openssl?', 'Is the openssl version affected?', label='Yes')
    vol_graph.edge('Is there openssl?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the openssl version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the openssl version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
