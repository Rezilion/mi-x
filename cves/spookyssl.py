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
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-3786

CVSS Score: N/A
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-3602

CVE-2022-3602 is a stack overflow vulnerability that occurs during the parsing of a X.509 TLS certificate 
post-validation. The vulnerability is caused due to a problem with the processing of Punycode while checking 
certificates. An attacker can potentially exploit this vulnerability by crafting a malicious certificate containing 
punycode in the domain of the email address field.
Then, the attacker has to have that certificate signed by a trusted CA. Once the client will try to verify the 
certificate chain it could possibly trigger a crash or even cause a Remote Code Execution.
CVE-2022-3786 differs from CVE-2022-3602 by the fact that it does not allow the attacker to control the content of the
 overflow which in this case is limited to the period character (`.`).
In this case, an attacker still needs to craft a malicious email address in a certificate signed by a trusted CA in 
order to overflow an arbitrary number of bytes containing the `.' character on the stack. This buffer overflow could 
result in a crash which can result in a denial of service.

MI-X supports two different methods to check if you have an affected OpenSSL version
Vector one - use the package manager to check if you have an affected OpenSSL that installed via the package manager.
Vector three - checks if the running processes are using an affected OpenSSL version.

Related Links:
https://www.rezilion.com/blog/clearing-the-fog-over-the-new-openssl-vulnerabilities/
'''
AFFECTED_VERSION_START_NUMBER = '3'
FIXED_VERSION = '3.0.7'
FIXED_UBUNTU_VERSIONS = {'Ubuntu 22.04': '3.0.2-0ubuntu1.7', 'Ubuntu 22.10': '3.0.5-2ubuntu2'}
OPENSSL = 'openssl'
REGEX_STRINGS = ['openssl-3.0.[1-6]', 'openssl_3.0.[1-6]', 'openssl 3.0.[1-6]']
REMEDIATION = 'Upgrade openssl version to 3.0.7 or higher, if Ubuntu 22.04 upgrade to 3.0.2-0ubuntu1.7, if Ubuntu ' \
                '22.10 upgrade to 3.0.5-2ubuntu2'
MITIGATION = 'If your servers are running the affected OpenSSL version, make sure they are segmented. It will avoid ' \
             'propagation to the entire network'


def check_affected_file(so_file, debug):
    """This function checks if the received file uses an affected OpenSSL version."""
    openssl_version = ''
    if os.path.isfile(so_file):
        strings_command = f'strings {so_file}'
        strings_content = run_command.command_output(strings_command, debug, container_name='')
        strings_content = strings_content.stdout
        if strings_content:
            for line in strings_content.split('\n'):
                line = line.lower()
                if OPENSSL in line:
                    for regex_string in REGEX_STRINGS:
                        openssl_regex = re.search(regex_string, line.lower())
                        if openssl_regex:
                            openssl_version = openssl_regex.group()
                            separator_char = openssl_version[7]
                            openssl_version = openssl_version.split(separator_char)[constants.END]
                            return openssl_version
    return openssl_version


def check_so_files(so_files, pid, debug):
    """This function loops over all loaded so files of the running process and checks if they are using an affected
    OpenSSL version."""
    so_files_and_openssl_versions = {}
    for so_file in so_files:
        if so_file not in so_files_and_openssl_versions:
            openssl_version = check_affected_file(so_file, debug)
            if openssl_version:
                so_files_and_openssl_versions[so_file] = openssl_version
    if so_files_and_openssl_versions:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} running process list of so files and affected'
                                                        f'OpenSSL versions:'))
        for so_path in so_files_and_openssl_versions:
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'{so_path} - '
                                                            f'{so_files_and_openssl_versions[so_path]}'))
    return so_files_and_openssl_versions


def check_executable_file(pid, debug, container_name):
    """This function check if the executable file of the process is using an affected OpenSSL version."""
    executable_file = process_functions.get_process_executable(pid, debug, container_name)
    openssl_version = ''
    if executable_file:
        openssl_version = check_affected_file(executable_file, debug)
        if openssl_version:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'The {pid} running process executable file is using an '
                                                            f'affected OpenSSL version:\n{executable_file} - '
                                                            f'{openssl_version}'))
    return openssl_version


def validate_processes_vector_two(state, pids, vulnerability, debug, container_name):
    """This function checks if the process uses an affected OpenSSL version."""
    for pid in pids:
        openssl_version = check_executable_file(pid, debug, container_name)
        so_files_and_openssl_versions = {}
        so_files = process_functions.get_loaded_so_files_of_a_process(pid, debug, container_name)
        if so_files:
            so_files_and_openssl_versions = check_so_files(so_files, pid, debug)
        if openssl_version or so_files_and_openssl_versions:
            state[pid] = status.process_vulnerable(pid, vulnerability)
    return state


def vector_two(state, debug, container_name):
    """This function performs the "vector two" of checking exploitability which is checking if there is a running
    process that loads libcrypto/libssl/openssl files that are using an affected OpenSSL version."""
    vulnerability = f'{VULNERABILITY} (the running processes check)'
    pids = process_functions.running_processes(debug, container_name)
    if pids:
        print(constants.FULL_QUESTION_MESSAGE.format('Are there running processes that use an affected OpenSSL '
                                                     'version?'))
        process_state = validate_processes_vector_two(state, pids, vulnerability, debug, container_name)
        if len(process_state) > 1:
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
    print(constants.FULL_QUESTION_MESSAGE.format('Is the OpenSSL version affected?'))
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
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected OpenSSL versions are lower than 3.0.7\nYour OpenSSL '
                                                        f'version which is: {openssl_version} is not affected'))
    return affected


def get_openssl_version(debug, container_name):
    """This function returns the OpenSSL version if exists."""
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
    """This function validates if the host is vulnerable to SpookySSL vulnerabilities."""
    state = {}
    state = vector_one(state, debug, container_name)
    state = vector_two(state, debug, container_name)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of SpookySSL."""
    vol_graph = graphviz.Digraph('G', filename=VULNERABILITY, format='png')
    commons.graph_start(VULNERABILITY, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is there OpenSSL?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is it Linux?', 'Are there running processes that use an affected OpenSSL versions?',  label='Yes')
    vol_graph.edge('Is there OpenSSL?', 'Is the OpenSSL version affected?', label='Yes')
    vol_graph.edge('Is there OpenSSL?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is the OpenSSL version affected?', 'Vulnerable', label='Yes')
    vol_graph.edge('Is the OpenSSL version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Are there running processes that use an affected OpenSSL versions?', 'Vulnerable', label='Yes')
    vol_graph.edge('Are there running processes that use an affected OpenSSL versions?', 'Not Vulnerable', label='No')
    commons.graph_end(vol_graph)


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
