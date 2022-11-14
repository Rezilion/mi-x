"""
Support for re, version from packaging and other modules written to avoid repetitive code.
"""
import re
from packaging import version
from modules import constants, graph_functions, status, run_command, file_functions, os_release, receive_package, process_functions

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
DYNAMIC = 'dynamically'
STATIC = 'statically'
AFFECTED_DEPENDENCIES = ['openssl.so', 'libssl.so', 'libcrypto.so']
REGEX_STRINGS = ['openssl-3\.0\.[1-6]', 'openssl_3\.0\.[1-6]', 'openssl 3\.0\.[1-6]']
REMEDIATION = 'Upgrade openssl version to 3.0.7 or higher, if Ubuntu 22.04 upgrade to 3.0.2-0ubuntu1.7, if Ubuntu ' \
                '22.10 upgrade to 3.0.5-2ubuntu2'
MITIGATION = 'If your servers are running the affected OpenSSL version, make sure they are segmented. It will avoid ' \
             'propagation to the entire network'


def check_type_of_files(so_file, files_and_openssl_version, debug):
    """This function checks if the affected file loads an affected file or has the OpenSSL code in it."""
    list_dynamic_dependencies_command = f'ldd {so_file}'
    list_dynamic_dependencies_pipe = run_command.command_output(list_dynamic_dependencies_command, debug, container_name='')
    list_dynamic_dependencies = list_dynamic_dependencies_pipe.stdout
    type_and_dependencies = []
    if list_dynamic_dependencies:
        file_type = STATIC
        dependency_path_and_openssl_version = {}
        for line in list_dynamic_dependencies.split('\n'):
            for affected_dependency in AFFECTED_DEPENDENCIES:
                if affected_dependency in line:
                    file_type = DYNAMIC
                    dependency_path = line.split(' ')[2]
                    if dependency_path in files_and_openssl_version:
                        dependency_openssl_version = files_and_openssl_version[files_and_openssl_version]
                    else:
                        dependency_openssl_version = check_openssl_in_files(dependency_path, debug)
                    dependency_path_and_openssl_version[dependency_path] = dependency_openssl_version
        type_and_dependencies = [file_type, dependency_path_and_openssl_version]
    return type_and_dependencies


def add_to_dictionary(dictionary, key, value):
    """This function add a key to dictionary and if already exists, adds the value if not exists."""
    if 'list' in str(type(value)):
        if key in dictionary:
            if value not in dictionary[key]:
                dictionary[key] += value
        else:
            dictionary[key] = value
    elif 'str' in str(type(value)):
        if key in dictionary:
            if value not in dictionary[key]:
                dictionary[key].append(value)
        else:
            dictionary[key] = [value]
    return dictionary


def print_message(dynamically_files_and_pids, statically_files_and_pids, files_and_openssl_version, files_and_dependencies):
    """This function prints the output message of the affected files."""
    if dynamically_files_and_pids or statically_files_and_pids:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        if statically_files_and_pids:
            for file in statically_files_and_pids:
                openssl_version = files_and_openssl_version[file]
                pids = ", ".join(list(set(statically_files_and_pids[file])))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Statically linked file: {file}\nOpenSSL version: '
                                                                f'{openssl_version}\nUsed in the following processes: '
                                                                f'{pids}'))
        if dynamically_files_and_pids:
            for file in dynamically_files_and_pids:
                pids = ", ".join(list(set(dynamically_files_and_pids[file])))
                dependencies = ", ".join(list(set(files_and_dependencies[file])))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'Dynamically linked file: {file}\nUse the following '
                                                                f'dependency that uses an affected OpenSSL version: '
                                                                f'{dependencies}\nUsed in the following processes: '
                                                                f'{pids}'))
    else:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))


def create_message(files_and_pids, files_and_openssl_version, debug):
    """This function creates the statically and dynamically output message of the affected files."""
    dynamically_files_and_pids = {}
    statically_files_and_pids = {}
    files_and_dependencies = {}
    for file in files_and_pids:
        type_and_dependencies = check_type_of_files(file, files_and_openssl_version, debug)
        if type_and_dependencies:
            if type_and_dependencies[constants.START] == STATIC:
                pids = files_and_pids[file]
                statically_files_and_pids = add_to_dictionary(statically_files_and_pids, file, pids)
            else:
                process_dependencies = type_and_dependencies[constants.FIRST]
                for dependency in process_dependencies:
                    for file_path in files_and_pids:
                        if dependency in file_path:
                            files_and_dependencies = add_to_dictionary(files_and_dependencies, file, file_path)
                            pids = files_and_pids[file_path]
                            statically_files_and_pids = add_to_dictionary(statically_files_and_pids, file_path, pids)
                            pids = files_and_pids[file]
                            dynamically_files_and_pids = add_to_dictionary(dynamically_files_and_pids, file, pids)
    print_message(dynamically_files_and_pids, statically_files_and_pids, files_and_openssl_version, files_and_dependencies)


def check_openssl_in_files(so_file, debug):
    """This function checks if the received file uses an affected OpenSSL version."""
    openssl_version = ''
    if file_functions.check_file_existence(so_file, debug, container_name=''):
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
        state = status.vulnerable(vulnerability)
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


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
