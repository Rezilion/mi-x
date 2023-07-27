"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, graph_functions, status_functions, file_functions, apache_functions

FIRST_CVE_ID = 'CVE-2021-41773'
SECOND_CVE_ID = 'CVE-2021-42013'
VULNERABILITY = 'CVE-2021-41773 and CVE-2021-42013'
DESCRIPTION = f'''The initial fix for this vulnerability contained an additional vulnerability, your system will be
scanned for both CVE-2021-41773 and CVE-2021-42013.

{FIRST_CVE_ID}

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-41773

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-42013
 
An apache HTTP server vulnerability that can lead to Path Traversal Map URLs to Files and Remote Code Execution attacks 
on the apache HTTP server.
The code in Apache HTTPD version 2.4.49 changed the path normalization implemented and introduced a vulnerability. 
To avoid path traversal vulnerability, the code resolves the URL encoded values from the URI, however, 
the code fails to properly convert the second encoded value after the first one, allowing the '/.%2e/' segment to 
bypass the check, and via path traversal, access files and directories in the server's file system through the cgi-bin 
directory. The vulnerability affects directories that are not explicitly set as an alias but have the ‘require all 
granted’ permissions. Moreover, if the ‘mod_cgi’ module is also enabled in the configuration file, the attacker will be 
able to leverage the path traversal vulnerability to execute code remotely.

{SECOND_CVE_ID}

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-42013
 
When the fix for {FIRST_CVE_ID} was released in the 2.4.50 version, this vulnerability was discovered.
The normalization function in 2.4.50 checked for the ‘%2e’ HTML URL encoding value, however it missed checking HTML URL 
encoding values of the HTML URL encoding values (double HTML URL encoding values) for example: '%%32%65' - (2 in hex is  
32 and e in hex is 65). Attackers can exploit the same vulnerability but using the '.%%32%65' instead of the '.%2e'.
Same as {FIRST_CVE_ID}, if the ‘mod_cgi’ module is also enabled in the configuration file, the attacker will be able to 
leverage the path traversal vulnerability to execute code remotely.

Related Links:
https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013
https://blogs.juniper.net/en-us/threat-research/apache-http-server-cve-2021-42013-and-cve-2021-41773-exploited
'''
NAME_FIELD = 'NAME='
FIRST_AFFECTED_VERSION = '2.4.49'
SECOND_AFFECTED_VERSION = '2.4.50'
REMEDIATION = 'Upgrade Apache version to 2.4.51 or higher.'
CHANGE_PERMISSIONS = 'Change the permissions from "Require all granted" to "Require all denied" in the relevant ' \
                     'directories'
RESTART = 'After making the changes, remember to restart the server for the modifications to take effect'
MITIGATION_1 = f'{CHANGE_PERMISSIONS}\n{RESTART}'
MITIGATION_2 = f'{CHANGE_PERMISSIONS}\nDisable the cgi_module and cgid_module by adding the "#" at the beginning of ' \
               f'the cgi_module and cgid_module lines in the configuration file\n{RESTART}'


def parse_directory_name(directory):
    """This function returns the directory after removing unnecessary characters."""
    directory = directory.replace('"', '').replace("'", '').replace(' ', '')
    if directory != '/' and directory.endswith('/'):
        directory = directory[:-1]
    return directory


def check_vulnerable_configuration(debug, container_name):
    """This function checks if the vulnerable configuration is set in the configuration file."""
    configuration_content = apache_functions.apache_configuration_file(debug, container_name)
    if configuration_content == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    cgi_bin_directory = None
    directory_name = None
    alias_module_section = False
    directory_section = False
    directories = []
    cgi_bin_required_all_granted = False
    print(constants.FULL_QUESTION_MESSAGE.format('Does the configuration have the vulnerable configuration set?\n1. '
                                                 'The cgi-bin directory must be set as an alias module.\n2. The cgi-bin '
                                                 'directory must be set to "Require all granted".\n3. At least another '
                                                 'directory must be set to "Require all granted")'))
    for line in configuration_content:
        if line.startswith('<IfModule alias_module>'):
            alias_module_section = True
        elif line.startswith('</IfModule>'):
            alias_module_section = False
        if alias_module_section and 'ScriptAlias /cgi-bin/' in line:
            cgi_bin_directory = line.split('ScriptAlias /cgi-bin/')[1]
            if 'cgi-bin' in cgi_bin_directory:
                cgi_bin_directory = parse_directory_name(cgi_bin_directory)
        if line.startswith('<Directory'):
            directory_section = True
            directory_name = line.split('<Directory')[1].split('>')[0]
            directory_name = parse_directory_name(directory_name)
        if directory_section and 'Require all granted' in line:
            if cgi_bin_directory and (directory_name == cgi_bin_directory):
                cgi_bin_required_all_granted = True
            else:
                directories.append(directory_name)
        if line.startswith('</Directory>'):
            directory_section = False
    if cgi_bin_required_all_granted and directories:
        directories_str = ', '.join(directories)
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The vulnerable configuration is set in the configuration file'
                                                        f'\nThe following directories have "Require all granted" '
                                                        f'permissions: {directories_str}'))
        return True
    elif not cgi_bin_directory:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('The cgi-bin is not configured as an alias module'))
    elif not cgi_bin_required_all_granted:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('The cgi-bin permission is not set to "Require all granted"'))
    elif not directories:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
        print(constants.FULL_EXPLANATION_MESSAGE.format('No directories with "Require all granted" permissions'))
    return False


def check_apache_version(apache_output):
    """This function checks if the Apache HTTP Server version is affected."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is apache version affected?'))
    version = apache_functions.get_apache_version(apache_output)
    if not version:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported version value'))
        return constants.UNSUPPORTED
    if FIRST_AFFECTED_VERSION == version:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected apache versions : {FIRST_AFFECTED_VERSION}\nYour '
                                                        f'apache version: {version}\nYour apache version is affected'))
        return FIRST_CVE_ID
    if SECOND_AFFECTED_VERSION == version:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected apache versions : {FIRST_AFFECTED_VERSION} and'
                                                        f' {SECOND_AFFECTED_VERSION}\nYour apache version: '
                                                        f'{version}\nYour apache version is affected'))
        return SECOND_CVE_ID
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Affected apache versions : {FIRST_AFFECTED_VERSION} and'
                                                    f' {SECOND_AFFECTED_VERSION}\nYour apache version: '
                                                    f'{version}\nYour apache version is not affected'))
    return ''


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2021-41773 or CVE-2021-42013."""
    state = {}
    apache_output = apache_functions.check_apache_types(debug, container_name)
    if apache_output:
        affected_version = check_apache_version(apache_output)
        if affected_version == constants.UNSUPPORTED:
            state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
        elif affected_version:
            vulnerable_configuration = check_vulnerable_configuration(debug, container_name)
            if vulnerable_configuration == constants.UNSUPPORTED:
                state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
            elif vulnerable_configuration:
                cgi_module_name = 'LoadModule cgi_module modules/mod_cgi.so'
                cgid_module_name = 'LoadModule cgid_module modules/mod_cgid.so'
                cgi_modules = apache_functions.loaded_module(cgi_module_name, debug, container_name)
                cgid_module = apache_functions.loaded_module(cgid_module_name, debug, container_name)
                if affected_version == FIRST_CVE_ID:
                    vulnerability = VULNERABILITY
                else:
                    vulnerability = SECOND_CVE_ID
                if (cgi_modules == constants.UNSUPPORTED or not cgi_modules) and (cgid_module == constants.UNSUPPORTED or not cgid_module):
                    state[vulnerability] = status_functions.vulnerable(f'{vulnerability} - Path Traversal - Map URLs to Files')
                    status_functions.remediation_mitigation(REMEDIATION, MITIGATION_1)
                else:
                    state[vulnerability] = status_functions.vulnerable(f'{vulnerability} - Path Traversal - Remote Code Execution')
                    status_functions.remediation_mitigation(REMEDIATION, MITIGATION_2)
            else:
                state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
        else:
            state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    else:
        state[VULNERABILITY] = status_functions.not_vulnerable(VULNERABILITY)
    return state


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2021-41773 or
    CVE-2021-42013."""
    vulnerability_graph = graph_functions.generate_graph(VULNERABILITY)
    vulnerability_graph.edge('Is it Linux?', 'Is host distribution affected?', label='Yes')
    vulnerability_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is host distribution affected?', 'Is Apache HTTP Server installed?', label='Yes')
    vulnerability_graph.edge('Is host distribution affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is Apache HTTP Server installed?', 'Is apache version affected?', label='Yes')
    vulnerability_graph.edge('Is Apache HTTP Server installed?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is apache version affected?', 'Is configuration file set the filesystem directory "Require '
                                                  'all granted"?', label='Yes')
    vulnerability_graph.edge('Is apache version affected?', 'Not Vulnerable', label='No')
    vulnerability_graph.edge('Is configuration file set the filesystem directory "Require all granted"?', 'Is "cgi_module" '
                                                                                                'loaded?', label='Yes')
    vulnerability_graph.edge('Is configuration file set the filesystem directory "Require all granted"?', 'Not Vulnerable',
                   label='No')
    vulnerability_graph.edge('Is "cgi_module" loaded?', 'Vulnerable to Path Traversal and Remote Code Execution', label='Yes')
    vulnerability_graph.edge('Is "cgi_module" loaded?', 'Vulnerable to Path Traversal', label='No')
    vulnerability_graph.view()


def main(description, graph, debug, container_name):
    """This is the main function."""
    if description:
        print(f'\n{DESCRIPTION}')
    state = validate(debug, container_name)
    if graph:
        validation_flow_chart()
    return state
