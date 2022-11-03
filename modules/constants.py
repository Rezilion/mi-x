"""
This file stores all of the repetitive constant variables.
"""
# Colors.
VULNERABLE = '\u001b[48;5;1m'
NOT_DETERMINED = '\u001b[48;5;3m'
NOT_VULNERABLE = '\u001b[48;5;2m'
NEGATIVE_RESULT = '\u001b[38;5;1m'
NEUTRAL_RESULT = '\u001b[38;5;3m'
POSITIVE_RESULT = '\u001b[38;5;2m'
QUESTION = '\u001b[4m\u001b[38;5;90m'
REMEDIATION_TITLE = '\u001b[4m\u001b[38;5;20m'
MITIGATION_TITLE = '\u001b[4m\u001b[38;5;32m'
REMEDIATION = '\u001b[38;5;20m'
MITIGATION = '\u001b[38;5;32m'
EXPLANATION = '\u001b[38;5;242m'
BASIC_COLOR = '\u001b[0m'

# Return value.
UNSUPPORTED = 'Unsupported'

# List indexes.
START = 0
FIRST = 1
END = -1

# Messages.
NOT_SUPPORTED_MESSAGE = 'For now, we do not support {} mode scanning for this vulnerability'
VULNERABLE_MESSAGE = 'Your system is vulnerable to {}'
PROCESS_VULNERABLE_MESSAGE = '{} process is vulnerable to {}'
NOT_DETERMINED_MESSAGE = 'Can not determine {} vulnerability status'
PROCESS_NOT_DETERMINED_MESSAGE = 'Can not determine if process {} is vulnerable to {}'
NOT_VULNERABLE_MESSAGE = 'Your system is not vulnerable to {}'
PROCESS_NOT_VULNERABLE_MESSAGE = '{} process is not vulnerable to {}'
EMPTY_MESSAGE = '{}'
REMEDIATION_MESSAGE = f'{REMEDIATION_TITLE}Remediation:\n{BASIC_COLOR}'
MITIGATION_MESSAGE = f'{MITIGATION_TITLE}Mitigation:\n{BASIC_COLOR}'
FULL_NOT_SUPPORTED_MESSAGE = f'{EXPLANATION}{NOT_SUPPORTED_MESSAGE}{BASIC_COLOR}'
FULL_VULNERABLE_MESSAGE = f'{VULNERABLE}{VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_VULNERABLE_MESSAGE = f'{VULNERABLE}{PROCESS_VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_NOT_DETERMINED_MESSAGE = f'{NOT_DETERMINED}{NOT_DETERMINED_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_NOT_DETERMINED_MESSAGE = f'{NOT_DETERMINED}{PROCESS_NOT_DETERMINED_MESSAGE}{BASIC_COLOR}'
FULL_NOT_VULNERABLE_MESSAGE = f'{NOT_VULNERABLE}{NOT_VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_NOT_VULNERABLE_MESSAGE = f'{NOT_VULNERABLE}{PROCESS_NOT_VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_POSITIVE_RESULT_MESSAGE = f'{POSITIVE_RESULT}{EMPTY_MESSAGE}{BASIC_COLOR}'
FULL_NEUTRAL_RESULT_MESSAGE = f'{NEUTRAL_RESULT}{EMPTY_MESSAGE}{BASIC_COLOR}'
FULL_NEGATIVE_RESULT_MESSAGE = f'{NEGATIVE_RESULT}{EMPTY_MESSAGE}{BASIC_COLOR}'
FULL_QUESTION_MESSAGE = f'{QUESTION}{EMPTY_MESSAGE}{BASIC_COLOR}'
FULL_EXPLANATION_MESSAGE = f'{EXPLANATION}{EMPTY_MESSAGE}{BASIC_COLOR}'
FULL_REMEDIATION_MESSAGE = f'{REMEDIATION_MESSAGE}{REMEDIATION}{EMPTY_MESSAGE}{BASIC_COLOR}'
FULL_MITIGATION_MESSAGE = f'{MITIGATION_MESSAGE}{MITIGATION}{EMPTY_MESSAGE}{BASIC_COLOR}'
NOT_INSTALLED_MESSAGE = '{} is not installed on your system\nYou can install it using pip command:\npip install {}'

# Docker commands.
DOCKER_EXEC_COMMAND = 'sudo docker exec -it {} /bin/{} -c "{}"'
DOCKER_INSPECT_COMMAND = 'sudo docker inspect {}'

# Linux distribution divided by types.
APT_DISTRIBUTIONS = ['Ubuntu', 'Debian']
RPM_DISTRIBUTIONS = ['Red', 'Centos', 'Fedora', 'SUSE', 'SLES', 'Amazon']

# Graphviz.
GRAPH_VULNERABLE = 'Vulnerable'
GRAPH_NOT_VULNERABLE = 'Not Vulnerable'
GRAPH_VULNERABLE_MESSAGE = 'Vulnerable to {}'
GRAPH_NOT_VULNERABLE_MESSAGE = 'Not Vulnerable to {}'

# States.
VULNERABLE = 'vulnerable'
NOT_VULNERABLE = 'not vulnerable'
NOT_DETERMINED = 'not determined'

# Duplicates vulnerabilities names.
DUPLICATE_VULNERABILITIES_NAMES = {'cve_2014_6271': 'shellshock', 'cve_2014_6277': 'shellshock',
                                   'cve_2014_6278': 'shellshock', 'cve_2014_7169': 'shellshock',
                                   'cve_2014_7186': 'shellshock', 'cve_2014_7187': 'shellshock',
                                   'cve_2021_44228': 'log4shell', 'cve_2021_45046': 'log4shell',
                                   'cve_2021_4104': 'log4shell', 'cve_2021_45105': 'log4shell',
                                   'cve_2021_44832': 'log4shell', 'cve_2022_29799': 'nimbuspwn',
                                   'cve_2022_29800': 'nimbuspwn', 'cve_2022_3786': 'spookyssl',
                                   'cve_2022_3602': 'spookyssl', 'heartbleed': 'cve_2014_0160',
                                   'ghost': 'cve_2015_0235', 'dirty_cow': 'cve_2016_5195',
                                   'meltdown': 'cve_2017_5754', 'huge_dirty_cow': 'cve_2017_1000405',
                                   'ghostcat': 'cve_2020_1938', 'pwnkit': 'cve_2021_4034',
                                   'cve_2021_42013': 'cve_2021_41773', 'dirty_pipe': 'cve_2022_0847',
                                   'spring4shell': 'cve_2022_22965'}

VULNERABILITIES_WITH_MULTIPLE_CVES = {'spectre': ['cve_2017_5715', 'cve_2017_5753', 'cve_2017_5754'],
                                      'dirty_cred': ['cve_2021_4154', 'cve_2022_2588']}

ALL_VULNERABILITIES = ['cve_2014_0160', 'cve_2015_0235', 'cve_2016_5195', 'cve_2017_5715', 'cve_2017_5753',
                       'cve_2017_5754', 'cve_2017_1000405', 'cve_2020_1938', 'cve_2021_3177', 'cve_2021_4034',
                       'cve_2021_4154', 'cve_2021_41773', 'cve_2022_0847', 'cve_2022_22965', 'cve_2022_25636',
                       'log4shell', 'shellshock', 'nimbuspwn', 'spookyssl']

LINUX_VULNERABILITIES = ['cve_2014_0160', 'cve_2015_0235', 'cve_2016_5195', 'cve_2017_5715', 'cve_2017_5753',
                       'cve_2017_5754', 'cve_2017_1000405', 'cve_2020_1938', 'cve_2021_3177', 'cve_2021_4034',
                       'cve_2021_4154', 'cve_2021_41773', 'cve_2022_0847', 'cve_2022_22965', 'cve_2022_25636',
                       'log4shell', 'shellshock', 'nimbuspwn', 'spookyssl']

SUPPORTED_ALPINE_VULNERABILITIES = ['cve_2022_22965', 'log4shell']
