"""
Support for re, version from packaging and other modules written to avoid repetitive code.
"""
import re
from packaging import version
from modules import constants, graph_functions, status_functions, file_functions, os_release_functions, package_functions, process_functions

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
Vector two - checks if the running processes are using an affected OpenSSL version by analyzing the process memory.

Related Links:
https://www.rezilion.com/blog/clearing-the-fog-over-the-new-openssl-vulnerabilities/
'''
AFFECTED_VERSION_START_NUMBER = '3'
FIXED_VERSION = '3.0.7'
FIXED_UBUNTU_VERSIONS = {'Ubuntu 22.04': '3.0.2-0ubuntu1.7', 'Ubuntu 22.10': '3.0.5-2ubuntu2'}
OPENSSL = 'openssl'
STATIC = ['static']
LIBCRYPTO = 'libcrypto.so'
REGEX_STRINGS = ['openssl-3\.0\.[1-6]', 'openssl_3\.0\.[1-6]', 'openssl 3\.0\.[1-6]']
REMEDIATION = 'Upgrade openssl version to 3.0.7 or higher, if Ubuntu 22.04 upgrade to 3.0.2-0ubuntu1.7, if Ubuntu ' \
              '22.10 upgrade to 3.0.5-2ubuntu2'
MITIGATION = 'If your servers are running the affected OpenSSL version, make sure they are segmented. It will avoid ' \
             'propagation to the entire network'


def check_if_dependency_exists(dependencies, affected_file, files_and_openssl_version, debug):
    """This function checks if the affected file is loading an affected file or has the OpenSSL code in it."""
    dependency_path_and_openssl_version = {}
    for line in dependencies.split('\n'):
        if affected_file in line:
            dependency_path = line.split(' ')[2]
            if dependency_path in files_and_openssl_version:
                dependency_openssl_version = files_and_openssl_version[dependency_path]
            else:
                dependency_openssl_version = check_openssl_in_files(dependency_path, debug)
            dependency_path_and_openssl_version[dependency_path] = dependency_openssl_version
    return dependency_path_and_openssl_version


def check_type_of_files(so_file, files_and_openssl_version, affected_files, debug):
    """This function returns the information about the file's type."""
    type_and_dependencies = []
    list_dynamic_dependencies = process_functions.get_file_dependencies(so_file, debug)
    if list_dynamic_dependencies:
        for affected_file in affected_files:
            dependency = check_if_dependency_exists(list_dynamic_dependencies, affected_file, files_and_openssl_version,
                                                    debug)
            if dependency:
                type_and_dependencies.append(dependency)
    return type_and_dependencies


def add_to_dictionary(dictionary, key, value):
    """This function add a key to dictionary and if already exists, adds the value if not exists."""
    if key in dictionary:
        if value not in dictionary[key]:
            dictionary[key] += value
    else:
        dictionary[key] = value
    return dictionary


def print_message(dynamically_files_and_pids, potentially_affected_files_and_pids, files_and_openssl_version, files_and_dependencies, debug):
    """This function prints the output message of the affected files."""
    if dynamically_files_and_pids or potentially_affected_files_and_pids:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        affected_files = {}
        libcrypto_file = [item for item in potentially_affected_files_and_pids if LIBCRYPTO in item][0]
        libcrypto_pids = potentially_affected_files_and_pids[libcrypto_file]
        potentially_affected_files = [item for item in potentially_affected_files_and_pids if
                                               LIBCRYPTO not in item]
        affected_files = add_to_dictionary(affected_files, libcrypto_file, libcrypto_pids)
        if potentially_affected_files:
            for file in potentially_affected_files:
                pids = potentially_affected_files_and_pids[file]
                dependencies = check_type_of_files(file, files_and_openssl_version, potentially_affected_files, debug)
                if dependencies:
                    dynamically_files_and_pids = add_to_dictionary(dynamically_files_and_pids, file, pids)
                else:
                    affected_files = add_to_dictionary(affected_files, file, pids)
        if dynamically_files_and_pids:
            for file in dynamically_files_and_pids:
                pids_string = ", ".join(list(set(dynamically_files_and_pids[file])))
                dependencies_string = ", ".join(list(set(files_and_dependencies[file])))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'This file {file} dynamically loads the file: '
                                                                f'{dependencies_string} which is affected by the '
                                                                f'SpookySSL vulnerabilities.\nThe following processes '
                                                                f'are loading this file: {pids_string}'))
        if affected_files:
            for file in affected_files:
                openssl_version = files_and_openssl_version[file]
                pids_string = ", ".join(list(set(affected_files[file])))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'This file {file} contains code associated with '
                                                                f'OpenSSL version: {openssl_version}, affected by the '
                                                                f'SpookySSL vulnerabilities\nThe following processes '
                                                                f'are loading this file: {pids_string}'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))


def create_message(files_and_pids, files_and_openssl_version, debug):
    """This function creates the statically and dynamically output message of the affected files."""
    dynamically_files_and_pids = {}
    potentially_affected_files_and_pids = {}
    files_and_dependencies = {}
    for file in files_and_pids:
        affected_files = [LIBCRYPTO]
        dependencies = check_type_of_files(file, files_and_openssl_version, affected_files, debug)
        if dependencies:
            for dependency in dependencies:
                for dependency_path in dependency:
                    for file_path in files_and_pids:
                        if dependency_path in file_path:
                            file_path_list = [file_path]
                            files_and_dependencies = add_to_dictionary(files_and_dependencies, file, file_path_list)
                            pids = files_and_pids[file_path]
                            potentially_affected_files_and_pids = add_to_dictionary(potentially_affected_files_and_pids,
                                                                                    file_path, pids)
                            pids = files_and_pids[file]
                            dynamically_files_and_pids = add_to_dictionary(dynamically_files_and_pids, file, pids)
        else:
            pids = files_and_pids[file]
            potentially_affected_files_and_pids = add_to_dictionary(potentially_affected_files_and_pids, file, pids)
    print_message(dynamically_files_and_pids, potentially_affected_files_and_pids, files_and_openssl_version,
                  files_and_dependencies, debug)


def check_openssl_in_files(so_file, debug):
    """This function checks if the received file uses an affected OpenSSL version."""
    openssl_version = ''
    strings_content = file_functions.get_file_strings(so_file, debug)
    if strings_content:
        for line in strings_content.split('\n'):
            line = line.lower()
            if OPENSSL in line:
                for regex_string in REGEX_STRINGS:
                    openssl_regex = re.search(regex_string, line.lower())
                    if openssl_regex:
                        openssl_version = openssl_regex.group()
                        openssl_version = openssl_version.split(OPENSSL)[-1][1 :]
                        return openssl_version
    return openssl_version


def validate_processes_vector_two(state, pids, vulnerability, debug, container_name):
    """This function checks if the process uses an affected OpenSSL version."""
    files_and_pids = {}
    files_and_openssl_version = {}
    for pid in pids:
        executable_file = process_functions.get_process_executable(pid, debug, container_name)
        if executable_file:
            if executable_file in files_and_pids:
                files_and_pids[executable_file].append(pid)
            else:
                openssl_version = check_openssl_in_files(executable_file, debug)
                if openssl_version:
                    files_and_pids[executable_file] = [pid]
                    files_and_openssl_version[executable_file] = openssl_version
        so_files = process_functions.get_loaded_so_files_of_a_process(pid, debug, container_name)
        if so_files:
            for so_file in so_files:
                if so_file in files_and_pids:
                    files_and_pids[so_file].append(pid)
                else:
                    openssl_version = check_openssl_in_files(so_file, debug)
                    if openssl_version:
                        files_and_pids[so_file] = [pid]
                        files_and_openssl_version[so_file] = openssl_version
    if files_and_pids:
        create_message(files_and_pids, files_and_openssl_version, debug)
        state = status_functions.vulnerable(vulnerability)
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
            status_functions.remediation_mitigation(REMEDIATION, MITIGATION)
            state[vulnerability] = process_state
        else:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format(f'There are no running processes loading so files that have'
                                                            f' an affected OpenSSL version'))
            state[vulnerability] = status_functions.not_vulnerable(vulnerability)
    else:
        state[vulnerability] = status_functions.not_vulnerable(vulnerability)
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
        host_information = os_release_functions.get_field(information_fields, debug, container_name)
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
    distribution = os_release_functions.get_field(information_fields, debug, container_name)
    openssl_version = ''
    if distribution in constants.APT_DISTRIBUTIONS:
        openssl_version = package_functions.package_version_apt(distribution, OPENSSL, debug, container_name)
    if distribution in constants.RPM_DISTRIBUTIONS:
        openssl_version = package_functions.package_version_rpm(distribution, OPENSSL, debug, container_name)
    return openssl_version


def vector_one(state, running_os_type, debug, container_name):
    """This function performs the "vector one" of checking exploit ability which is checking if the affected OpenSSL
    version installed using the package manager."""
    vulnerability = f'{VULNERABILITY} (the package manager check)'
    if running_os_type == constants.LINUX:
        openssl_version = get_openssl_version(debug, container_name)
    else:
        openssl_version = package_functions.get_package_version_windows(OPENSSL, debug, container_name)
    if openssl_version == constants.UNSUPPORTED:
        state[vulnerability] = status_functions.not_determined(vulnerability)
    elif openssl_version:
        if check_openssl_affected(openssl_version, debug, container_name):
            state[vulnerability] = status_functions.vulnerable(vulnerability)
            status_functions.remediation_mitigation(REMEDIATION, MITIGATION)
        else:
            state[vulnerability] = status_functions.not_vulnerable(vulnerability)
    else:
        state[vulnerability] = status_functions.not_vulnerable(vulnerability)
    return state


def validate(running_os_type, debug, container_name):
    """This function validates if the host is vulnerable to SpookySSL vulnerabilities."""
    state = {}
    state = vector_one(state, running_os_type, debug, container_name)
    if running_os_type == constants.LINUX:
        state = vector_two(state, debug, container_name)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of SpookySSL."""
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Is there OpenSSL?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is it Linux?', 'Are there running processes that use an affected OpenSSL version?',  label='Yes')
    vulnerability_graph.edge('Is there OpenSSL?', 'Is the OpenSSL version affected?', label='Yes')
    vulnerability_graph.edge('Is there OpenSSL?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is the OpenSSL version affected?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Is the OpenSSL version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Are there running processes that use an affected OpenSSL version?', 'Vulnerable', label='Yes')
    vulnerability_graph.edge('Are there running processes that use an affected OpenSSL version?', 'Not Vulnerable', label='No')
    vulnerability_graph.view()


def main(description, graph, running_os_type, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(running_os_type, debug, container_name)
    if graph:
        validation_flow_chart()
    return state
