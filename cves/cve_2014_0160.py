"""
Support for graphviz, version from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
from packaging import version
from modules import commons, constants, os_release, receive_package

CVE_ID = 'CVE-2014-0160'
DESCRIPTION = f'''Heartbleed

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/cve-2014-0160

{CVE_ID} is a programming mistake in a popular OpenSSL library that provides cryptographic services such as SSL/TLS to 
the applications and services.
Due to a missing/incorrect bounds check in the code, it is possible to return chunks of memory from a TLS peer (client 
or server) by sending invalid requests which are incorrectly processed.
Attackers can exploit the vulnerability and leak sensitive information such as the private key, account names and/or 
passwords.
 
Related Links:
https://heartbleed.com/
https://www.synopsys.com/blogs/software-security/heartbleed-vulnerability-appsec-deep-dive/
'''
AFFECTED_VERSIONS_MESSAGE = '1.0.1 up to including 1.0.1g and 1.0.2 up to including 1.0.2beta1'
AFFECTED_VERSIONS = ['1.0.1', '1.0.1f', '1.0.2', '1.0.2beta1']
MAX_AFFECTED_VERSION = '2.17'


def check_openssl_version(openssl_version):
    """This function checks if the GLIBC version is affected."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is openssl version affected?'))
    if version.parse(AFFECTED_VERSIONS[constants.START]) <= version.parse(openssl_version) <= \
            version.parse(AFFECTED_VERSIONS[constants.FIRST]) or \
            version.parse(openssl_version) == version.parse(AFFECTED_VERSIONS[2]) or \
            version.parse(openssl_version) == version.parse(AFFECTED_VERSIONS[constants.END]):
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected openssl versions are: {AFFECTED_VERSIONS_MESSAGE}\n'
                                                        f'Your openssl version which is: {openssl_version} is '
                                                        f'affected'))
        return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected openssl versions are between {AFFECTED_VERSIONS_MESSAGE}'
                                                    f'\nYour openssl version which is: {openssl_version} is not '
                                                    f'affected'))
    return False


def get_openssl_version(debug, container_name):
    information_fields = ['Distribution']
    distribution = os_release.get_field(information_fields, debug, container_name)
    package_name = 'openssl'
    return receive_package.package(distribution, package_name, debug, container_name)


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Heartbleed vulnerabilities."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        openssl_version = get_openssl_version(debug, container_name)
        if openssl_version == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif openssl_version:
            if check_openssl_version(openssl_version):
                print(constants.FULL_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Heartbleed."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there openssl?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there openssl?', 'Is the openssl version affected?', label='Yes')
    vol_graph.edge('Is there openssl?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the openssl version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the openssl version affected?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
