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
 
An apache HTTP server vulnerability that can lead to Path Traversal and Remote Code Execution on the apache HTTP server.
To avoid path traversal attack, the normalization function (only in apache 2.4.49 version) which is responsible for 
resolving the URL encoded values from the URI, checks the URI values one at a time. 
Hence, it misses ‘%2e’ and ‘%2f’ characters that represent dot and slash. If an attacker will ask for ‘dot dot slash‘
in this way ‘.%2e/‘ or ‘%2e%2e%ef‘, and the filesystem directory is set to "Require all granted", he will traverse back 
in the apache directories. With that, he can go whenever he wants and get access to sensitive files in the 
apache HTTP server. Moreover, if the ‘mod_cgi’ module is also enabled in the configuration file, 
the attacker will be able to leverage the path traversal vulnerability and call any binary on the system 
using HTTP POST requests.

{SECOND_CVE_ID}

CVSS Score: 9.8
NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2021-42013
 
When the fix for {FIRST_CVE_ID} was released in the 2.4.50 version, this vulnerability was discovered.
The normalization function in 2.4.50 checked for ‘%2e’ and ‘%2f’ strings, however it missed double URL encoding as: 
%%32%65 - (2 in hex is 32 and e in hex is 65).
So 2.4.50 apache version also misses the dot dot slash or Path Traversal attack in a case the filesystem directory is 
set to "Require all granted".
Same as {FIRST_CVE_ID}, if the ‘mod_cgi’ module is also enabled in the configuration file, the attacker will be able to 
leverage the path traversal vulnerability and call any binary on the system using HTTP POST requests.

Related Links:
https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013
https://blogs.juniper.net/en-us/threat-research/apache-http-server-cve-2021-42013-and-cve-2021-41773-exploited
'''
NAME_FIELD = 'NAME='
FIRST_AFFECTED_VERSION = '2.4.49'
SECOND_AFFECTED_VERSION = '2.4.50'
REMEDIATION = 'Upgrade Apache version to 2.4.51 or higher.'
MITIGATION_1 = 'Change the filesystem permissions in the <Directory /> field in the configuration file from ' \
               '"Require all granted" to "Require all denied"'
MITIGATION_2 = f'{MITIGATION_1}\nAlso disable the cgi_module\nOn RedHat, Fedora, CentOS and other rpm based ' \
               f'distributions:\nmv /etc/httpd/conf.modules.d/XX-cgi.conf /etc/httpd/conf.modules.d/XX-cgi.conf.disable' \
               f'\nOn Debian, Ubuntu and other Debian derivatives:\na2dismod cgi'


def filesystem_directory_configuration(debug, container_name):
    """This function checks if the filesystem directory is configured to 'Require all granted' or 'Require all
    denied'"""
    configuration_content = apache_functions.apache_configuration_file(debug, container_name)
    if configuration_content == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    start = configuration_content.index('<Directory />') + 1
    end = configuration_content.index('</Directory>')
    print(constants.FULL_QUESTION_MESSAGE.format('Is the filesystem directory in the configuration file set to "Require'
                                                 ' all granted"?'))
    if not start or not end:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no filesystem '
                                                        'directory configuration value'))
        return constants.UNSUPPORTED
    for line in configuration_content[start:end]:
        if 'Require all granted' in line:
            print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Apache configuration file sets the filesystem '
                                                            'directory to "Require all granted"'))
            return True
        if 'Require all denied' in line:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Apache configuration file sets the filesystem '
                                                            'directory to "Require all denied"'))
            return False
    print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine vulnerability status, no filesystem '
                                                    'directory configuration value'))
    return constants.UNSUPPORTED


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
            permissions = filesystem_directory_configuration(debug, container_name)
            if permissions == constants.UNSUPPORTED:
                state[VULNERABILITY] = status_functions.not_determined(VULNERABILITY)
            elif permissions:
                modules = apache_functions.loaded_modules('cgi_module', debug, container_name)
                if affected_version == FIRST_CVE_ID:
                    vulnerability = VULNERABILITY
                else:
                    vulnerability = SECOND_CVE_ID
                if modules == constants.UNSUPPORTED or not modules:
                    state[vulnerability] = status_functions.vulnerable(f'{vulnerability} - Path Traversal attack')
                    status_functions.remediation_mitigation(REMEDIATION, MITIGATION_1)
                else:
                    state[vulnerability] = status_functions.vulnerable(f'{vulnerability} - Path Traversal and Remote Code Execution attacks')
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
