"""
Support for os, semver, graphviz and other modules which written for avoiding repetitive code.
"""
import os
import semver
import graphviz
from Modules import run_command, apache as apache_functions, commons, constants

CVE_ID_ONE = 'CVE-2021-41773'
CVE_ID_TWO = 'CVE-2021-42013'
CVE_ID = 'CVE-2021-41773 or CVE-2021-42013'
SERVER_VERSION_FIELD = 'Server version:'
DESCRIPTION = f'''The initial fix for this vulnerability contained an additional vulnerability, your system will be
scanned for both CVE-2021-41773 and CVE-2021-42013.

{CVE_ID_ONE}

CVSS Score: 7.5
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
 
An apache HTTP server vulnerability that can lead to Path Traversal and Remote Code Execution on the apache HTTP server.
To avoid path traversal attack, the normalization function (only in apache 2.4.49 version) which is responsible for 
resolving the URL encoded values from the URI, checks the URI values one at a time. 
Hence, it misses ‘%2e’ and ‘%2f’ characters that represent dot and slash. If an attacker will ask for ‘dot dot slash‘
in this way ‘.%2e/‘ or ‘%2e%2e%ef‘, and the filesystem directory is set to "Require all granted", he will traverse back 
in the apache directories. With that, he can go whenever he wants and get access to sensitive files in the 
apache HTTP server. Moreover, if the ‘mod_cgi’ module is also enabled in the configuration file, 
the attacker will be able to leverage the path traversal vulnerability and call any binary on the system 
using HTTP POST requests.

{CVE_ID_TWO}

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-42013
 
When the fix for {CVE_ID_ONE} was released in the 2.4.50 version, this vulnerability was discovered.
The normalization function in 2.4.50 checked for ‘%2e’ and ‘%2f’ strings, however it missed double URL encoding as: 
%%32%65 - (2 in hex is 32 and e in hex is 65).
So 2.4.50 apache version also misses the dot dot slash or Path Traversal attack in a case the filesystem directory is 
set to "Require all granted".
Same as {CVE_ID_ONE}, if the ‘mod_cgi’ module is also enabled in the configuration file, the attacker will be able to 
leverage the path traversal vulnerability and call any binary on the system using HTTP POST requests.
'''
NAME_FIELD = 'NAME='
FIRST_AFFECTED_VERSION = '2.4.49'
SECOND_AFFECTED_VERSION = '2.4.50'


def filesystem_directory_configuration(configuration_content):
    """This function checks if the filesystem directory is configured to 'Require all granted' or 'Require all
    denied'"""
    start = configuration_content.index('<Directory />\n') + 1
    end = configuration_content.index('</Directory>\n')
    print(constants.FULL_QUESTION_MESSAGE.format('Is the filesystem directory in the configuration file set to "Require'
                                                 ' all granted"?'))
    if not start or not end:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no filesystem '
                                                        'directory configuration value'))
        return constants.UNSUPPORTED
    for line in configuration_content[start:end]:
        if 'Require all granted' in line:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('Apache configuration file sets the filesystem '
                                                            'directory to "Require all granted"'))
            return True
        if 'Require all denied' in line:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE)
            print(constants.FULL_EXPLANATION_MESSAGE.format('Apache configuration file sets the filesystem '
                                                            'directory to "Require all denied"'))
            return False
    print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no filesystem '
                                                    'directory configuration value'))
    return constants.UNSUPPORTED


def apache_configuration_file(apache, debug, container_name):
    """This function checks if the filesystem directory is set to "Require all granted" in the apache configuration
    file."""
    if apache == 'apache2':
        configuration_file_path = '/etc/apache2/apache2.conf'
    else:
        configuration_file_path = '/etc/httpd/conf/httpd.conf'
        if not os.path.isfile(configuration_file_path):
            configuration_file_path = 'etc/apache2/httpd.conf'
    configuration_content = commons.file_content(configuration_file_path, debug, container_name)
    if configuration_content:
        return filesystem_directory_configuration(configuration_content)
    return constants.UNSUPPORTED


def apache_version(apache, debug, container_name):
    """This function checks if the Apache HTTP Server version is vulnerable."""
    apache_command = f'{apache} -v'
    pipe_apache = run_command.command_output(apache_command, debug, container_name)
    apache = pipe_apache.stdout
    print(constants.FULL_QUESTION_MESSAGE.format('Is Apache HTTP Server installed?'))
    if not apache:
        print(constants.FULL_POSITIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server is not installed'))
        return False
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server is installed'))
    print(constants.FULL_QUESTION_MESSAGE.format('Is apache version affected?'))
    version = ''
    for field in apache.split('\n'):
        if SERVER_VERSION_FIELD in field:
            version = field.split('/')[constants.FIRST].split(' ')[constants.START]
    if not version:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Unsupported version value'))
        return constants.UNSUPPORTED
    if semver.compare(FIRST_AFFECTED_VERSION, version) == 0:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable apache versions : {FIRST_AFFECTED_VERSION} and'
                                                        f' {SECOND_AFFECTED_VERSION}\nYour apache version: '
                                                        f'{version}\nYour apache version is affected'))
        return 'CVE-2021-41773'
    if semver.compare(SECOND_AFFECTED_VERSION, version) == 0:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE)
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable apache versions : {FIRST_AFFECTED_VERSION} and'
                                                        f' {SECOND_AFFECTED_VERSION}\nYour apache version: '
                                                        f'{version}\nYour apache version is affected'))
        return 'CVE-2021-42013'
    print(constants.FULL_POSITIVE_RESULT_MESSAGE)
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'Vulnerable apache versions : {FIRST_AFFECTED_VERSION} and'
                                                    f' {SECOND_AFFECTED_VERSION}\nYour apache version: '
                                                    f'{version}\nYour apache version is not affected'))
    return False


def validate(debug, container_name):
    """This function validates if the host is vulnerable to CVE-2021-41773 or CVE-2021-42013."""
    if commons.check_linux_and_affected_distribution(CVE_ID, debug, container_name):
        apache = apache_functions.distribution_to_apache(debug, container_name)
        if apache == constants.UNSUPPORTED:
            print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
        elif apache:
            cve = apache_version(apache, debug, container_name)
            if cve:
                permissions = apache_configuration_file(apache, debug, container_name)
                if permissions == constants.UNSUPPORTED:
                    print(constants.FULL_NOT_DETERMINED_MESSAGE.format(CVE_ID))
                elif permissions:
                    modules = apache_functions.loaded_modules(apache, 'cgi_module', debug, container_name)
                    if modules == constants.UNSUPPORTED or not modules:
                        print(constants.FULL_VULNERABLE_MESSAGE.format(f'{CVE_ID} Path Traversal attack'))
                    else:
                        print(constants.FULL_VULNERABLE_MESSAGE.format(f'{CVE_ID} Path Traversal attack and Remote Code'
                                                                       f'Execution attacks'))
                else:
                    print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
            else:
                print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))
        else:
            print(constants.FULL_NOT_VULNERABLE_MESSAGE.format(CVE_ID))


def validation_flow_chart():
    """This function creates graph that shows the vulnerability validation process of CVE-2021-41773 or
    CVE-2021-42013."""
    vol_graph = graphviz.Digraph('G', filename=CVE_ID)
    commons.graph_start(CVE_ID, vol_graph)
    vol_graph.edge('Is it Linux?', 'Is host distribution affected?', label='Yes')
    vol_graph.edge('Is it Linux?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is host distribution affected?', 'Is Apache HTTP Server installed?', label='Yes')
    vol_graph.edge('Is host distribution affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is Apache HTTP Server installed?', 'Is apache version affected?', label='Yes')
    vol_graph.edge('Is Apache HTTP Server installed?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is apache version affected?', 'Is configuration file set the filesystem directory "Require '
                                                  'all granted"?', label='Yes')
    vol_graph.edge('Is apache version affected?', 'Not Vulnerable', label='No')
    vol_graph.edge('Is configuration file set the filesystem directory "Require all granted"?', 'Is "cgi_module" '
                                                                                                'loaded?', label='Yes')
    vol_graph.edge('Is configuration file set the filesystem directory "Require all granted"?', 'Not Vulnerable',
                   label='No')
    vol_graph.edge('Is "cgi_module" loaded?', 'Vulnerable to Path Traversal and Remote Code Execution', label='Yes')
    vol_graph.edge('Is "cgi_module" loaded?', 'Vulnerable to Path Traversal', label='No')
    commons.graph_end(vol_graph)


def main(describe, graph, debug, container_name):
    """This is the main function."""
    if describe:
        print(f'\n{DESCRIPTION}')
    validate(debug, container_name)
    if graph:
        validation_flow_chart()
