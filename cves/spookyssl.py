"""
Support for graphviz, re, version, os from packaging and other modules which written for avoiding repetitive code.
"""
import graphviz
import re
from packaging import version
import os
from modules import status, commons, constants, os_release, receive_package, process_functions, run_command

VULNERABILITY = 'Spooky SSL'
DESCRIPTION = f'''{VULNERABILITY} - CVE-2022-3786, CVE-2022-3602

CVSS Score: N/A 
NVD Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3786

CVSS Score: N/A
NVD Link: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3602

CVE-2022-3602 is a stack overflow vulnerability that occurs during the parsing of a X.509 TLS certificate 
post-validation. The vulnerability is caused due to a problem with the processing of Punycode while checking 
certificates. An attacker can potentially exploit this vulnerability by crafting a malicious certificate containing 
punycode in the domain of the email address field.
Then, the attacker has to have that certificate signed by a trusted CA. Once the client will try to verify the 
certificate chain it could possibly trigger a crash or even cause a Remote Code Execution.
CVE-2022-3786 differs from CVE-2022-3602 by the fact that it does not allow the attacker to control the content of the
 overflow which in this case is limited to the period character (`.`).
In this case, an attacker still needs to craft a malicious email address in a certificate signed by a trusted CA in 
order to overflow an arbitrary number of bytes containing the `.` character on the stack. This buffer overflow could 
result in a crash which can result in a denial of service.

MI-X supports three different methods to check if you have an affected OpenSSL
Vector one - use the package manager to check if you have an affected OpenSSL that installed via the package manager.
Vector two - checks if your system runs higher node version than 17.0.0 due to the fact that these versions of node use 
an affected OpenSSL version.
Vector three - checks if the running processes that are loading to memory an affected so files: OpenSSL/LibSSL/LibCrypto.

Related Links:
https://www.rezilion.com/blog/clearing-the-fog-over-the-new-openssl-vulnerabilities/
'''
AFFECTED_VERSION_START_NUMBER = '3'
FIXED_VERSION = '3.0.7'
FIXED_UBUNTU_VERSIONS = {'Ubuntu 22.04': '3.0.2-0ubuntu1.7', 'Ubuntu 22.10': '3.0.5-2ubuntu2'}
MIN_VULNERABLE_NODE_VERSIONS = '17.0.0'
SO_FILE_TYPES = ['openssl', 'libssl', 'libcrypto']
REGEX_STRING = 'openssl-3.0.[0-6]'
REMEDIATION = 'Upgrade openssl version to 3.0.7 or higher, if Ubuntu 22.04 upgrade to 3.0.2-0ubuntu1.7, if Ubuntu ' \
                '22.10 upgrade to 3.0.5-2ubuntu2'
MITIGATION = 'If your servers are running the affected OpenSSL version, make sure they are segmented. It will avoid ' \
             'propagation to the entire network'


def check_affected_os_file(so_path, debug, container_name):
    """This function checks if the running process is loading an affected OpenSSL file."""
    openssl_version = ''
    if os.path.isfile(so_path):
        strings_command = f'strings {so_path}'
        strings_content = run_command.command_output(strings_command, debug, container_name)
        strings_content = strings_content.stdout
        if strings_content:
            for line in strings_content.split('\n'):
                if 'openssl-' in line:
                    if re.search('openssl-3.0.[0-6]', line):
                        openssl_version = re.search(REGEX_STRING, strings_content).group()
                        openssl_version = openssl_version.split('-')[constants.END]
        else:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Unable to find strings on {so_path}'))
    else:
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The path to the so file found in the process maps: {so_path},'
                                                        f' is not a valid path'))
    return openssl_version


def validate_processes_vector_three(pids, vulnerability, debug, container_name):
    """This function loops over all processes and checks if they are loading to memory an affected so file."""
    state = {}
    for pid in pids:
        for so_file_type in SO_FILE_TYPES:
            so_path = process_functions.check_loaded_so_file_to_process(pid, so_file_type, debug, container_name)
            if so_path:
                if AFFECTED_VERSION_START_NUMBER in so_path.split('/')[constants.END]:
                    openssl_version = check_affected_os_file(so_path, debug, container_name)
                    if openssl_version:
                        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} running process is loading a so '
                                                                        f'file: {so_path} that has an affected OpenSSL '
                                                                        f'version: {openssl_version}'))
                        state[pid] = status.process_vulnerable(pid, vulnerability)
                    else:
                        state[pid] = status.process_not_determined(pid, vulnerability)
    return state


def vector_three(state, debug, container_name):
    """This function performs the "vector three" of checking exploitability which is checking if there is a running
    process that loads libcrypto/libssl/openssl files that are using an affected OpenSSL version."""
    vulnerability = f'{VULNERABILITY} (the so files check)'
    pids = process_functions.running_processes(debug, container_name)
    if pids:
        print(constants.FULL_QUESTION_MESSAGE.format('Are there running processes that load "openssl/libssl/libcrypto" '
                                                     'so files??'))
        process_state = validate_processes_vector_three(pids, vulnerability, debug, container_name)
        if process_state:
            status.remediation_mitigation(REMEDIATION, MITIGATION)
            state[vulnerability] = process_state
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running processes loading so files that have'
                                                            f' an affected OpenSSL version'))
            state[vulnerability] = status.not_vulnerable(vulnerability)
    else:
        state[vulnerability] = status.not_vulnerable(vulnerability)
    return state


def validate_processes_vector_two(state, pids, vulnerability, debug, container_name):
    """This function loops over all Node processes and checks if their versions known to be using an affected OpenSSL
    version."""
    for pid in pids:
        print(constants.FULL_QUESTION_MESSAGE.format('Is Node version affected?'))
        version_output = process_functions.process_executable_version(pid, debug, container_name)
        if version_output == constants.UNSUPPORTED:
            state[pid] = status.process_not_determined(pid, vulnerability)
        node_version = version_output[constants.FIRST:]
        if version.parse(node_version) >= version.parse(MIN_VULNERABLE_NODE_VERSIONS):
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Node versions that are equal or higher than 17.0.0 are '
                                                            f'using OpenSSL versions 3.0.x\nYour node version which is:'
                                                            f' {node_version}, is affected'))
            state[pid] = status.process_vulnerable(pid, vulnerability)
            status.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'Node versions that are equal or higher than 17.0.0 are '
                                                            f'using OpenSSL versions 3.0.x\nYour node version which is:'
                                                            f' {node_version}, is not affected'))
            state[pid] = status.process_not_vulnerable(pid, vulnerability)
    return state


def vector_two(state, debug, container_name):
    """This function performs the "vector two" of checking exploitability which is checking if there is a running node
    process which is using the affected OpenSSL version."""
    vulnerability = f'{VULNERABILITY} (the node check)'
    pids = process_functions.pids_consolidation('node', debug, container_name)
    if pids:
        state[vulnerability] = validate_processes_vector_two(state, pids, vulnerability, debug, container_name)
    else:
        state[vulnerability] = status.not_vulnerable(vulnerability)
    return state


def compare_versions(openssl_version, fixed_openssl_version):
    """This function compares the OpenSSL versions."""
    affected = False
    if version.parse(openssl_version) < version.parse(fixed_openssl_version):
        affected = True
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected OpenSSL versions are lower than '
                                                        f'{fixed_openssl_version}\nYour OpenSSL version which is: '
                                                        f'{openssl_version} is affected'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected OpenSSL versions are lower than '
                                                        f'{fixed_openssl_version}\nYour OpenSSL version which is: '
                                                        f'{openssl_version} is not affected'))
    return affected


def check_openssl_affected(openssl_version, debug, container_name):
    """This function checks if the OpenSSL version is affected."""
    affected = False
    print(constants.FULL_QUESTION_MESSAGE.format('Is OpenSSL version affected?'))
    if openssl_version.startswith(AFFECTED_VERSION_START_NUMBER):
        information_fields = ['Distribution', 'Version']
        host_information = os_release.get_field(information_fields, debug, container_name)
        if host_information in FIXED_UBUNTU_VERSIONS:
            fixed_openssl_version = FIXED_UBUNTU_VERSIONS[host_information]
        else:
            fixed_openssl_version = FIXED_VERSION
        affected = compare_versions(openssl_version, fixed_openssl_version)
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected OpenSSL versions are lower than 3.0.7\nYour '
                                                        f'OpenSSL version which is: {openssl_version} is not '
                                                        f'affected'))
    return affected


def get_openssl_version(debug, container_name):
    """This function returns the openssl version if exists."""
    information_fields = ['Distribution']
    distribution = os_release.get_field(information_fields, debug, container_name)
    package_name = 'openssl'
    openssl_version = ''
    if distribution in constants.APT_DISTRIBUTIONS:
        openssl_version = receive_package.package_version_apt(distribution, package_name, debug, container_name)
    if distribution in constants.RPM_DISTRIBUTIONS:
        openssl_version =  receive_package.package_version_rpm(distribution, package_name, debug, container_name)
    return openssl_version


def vector_one(state, debug, container_name):
    """This function performs the "vector one" of checking exploitability which is checking if the affected OpenSSL
    version installed using the package manager."""
    vulnerability = f'{VULNERABILITY} (the package manager check)'
    openssl_version = get_openssl_version(debug, container_name)
    if openssl_version == constants.UNSUPPORTED:
        state[vulnerability] = status.not_determined(vulnerability)
    elif openssl_version:
        if check_openssl_affected(openssl_version, debug, container_name):
            state[vulnerability] = status.vulnerable(vulnerability)
            status.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            state[vulnerability] = status.not_vulnerable(vulnerability)
    else:
        state[vulnerability] = status.not_vulnerable(vulnerability)
    return state


def validate(debug, container_name):
    """This function validates if the host is vulnerable to Heartbleed vulnerabilities."""
    state = {}
    state = vector_one(state, debug, container_name)
    state = vector_two(state, debug, container_name)
    state = vector_three(state, debug, container_name)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of Heartbleed."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there OpenSSl?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is there OpenSSl?', 'Is the OpenSSl version affected?', label='Yes')
    vol_graph.edge('Is there OpenSSl?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the OpenSSl version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the OpenSSl version affected?', 'Is there node version that uses an affected OpenSSl version?',
                   label='No')
    vol_graph.edge('s there node version that uses an affected OpenSSl version?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is there a Node.js version that uses an affected OpenSSL version?', 'Is there running process that uses an affected OpenSSL version?', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
