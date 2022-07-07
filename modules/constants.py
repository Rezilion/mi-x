"""
This file stores all of the repetitive constant variables.
"""
# Colors.
EXPLOITABLE = '\033[101m'
NOT_DETERMINED = '\033[103m'
NOT_EXPLOITABLE = '\033[102m'
POSITIVE_RESULT = '\033[92m'
NEUTRAL_RESULT = '\033[93m'
NEGATIVE_RESULT = '\033[91m'
QUESTION = '\033[94m'
EXPLANATION = '\033[90m'
BASIC_COLOR = '\033[00m'

# Return value.
UNSUPPORTED = 'Unsupported'

# List indexes.
START = 0
FIRST = 1
END = -1

# Messages.
EXPLOITABLE_MESSAGE = 'Your system is exploitable to {}'
PROCESS_EXPLOITABLE_MESSAGE = '{} process is exploitable to {}'
NOT_DETERMINED_MESSAGE = 'Can not determine {} vulnerability status'
PROCESS_NOT_DETERMINED_MESSAGE = 'Can not determine {} vulnerability to {} process'
NOT_EXPLOITABLE_MESSAGE = 'Your system is not exploitable to {}'
PROCESS_NOT_EXPLOITABLE_MESSAGE = '{} process is not exploitable to {}'
NEUTRAL_RESULT_MESSAGE = '{}'
QUESTION_MESSAGE = '{}'
EXPLANATION_MESSAGE = '{}'
FULL_EXPLOITABLE_MESSAGE = f'{EXPLOITABLE}{EXPLOITABLE_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_EXPLOITABLE_MESSAGE = f'{EXPLOITABLE}{PROCESS_EXPLOITABLE_MESSAGE}{BASIC_COLOR}'
FULL_NOT_DETERMINED_MESSAGE = f'{NOT_DETERMINED}{NOT_DETERMINED_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_NOT_DETERMINED_MESSAGE = f'{NOT_DETERMINED}{PROCESS_NOT_DETERMINED_MESSAGE}{BASIC_COLOR}'
FULL_NOT_EXPLOITABLE_MESSAGE = f'{NOT_EXPLOITABLE}{NOT_EXPLOITABLE_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_NOT_EXPLOITABLE_MESSAGE = f'{NOT_EXPLOITABLE}{PROCESS_NOT_EXPLOITABLE_MESSAGE}{BASIC_COLOR}'
FULL_POSITIVE_RESULT_MESSAGE = f'{POSITIVE_RESULT}No{BASIC_COLOR}'
FULL_NEUTRAL_RESULT_MESSAGE = f'{NEUTRAL_RESULT}{NEUTRAL_RESULT_MESSAGE}{BASIC_COLOR}'
FULL_NEGATIVE_RESULT_MESSAGE = f'{NEGATIVE_RESULT}Yes{BASIC_COLOR}'
FULL_QUESTION_MESSAGE = f'{QUESTION}{QUESTION_MESSAGE}{BASIC_COLOR}'
FULL_EXPLANATION_MESSAGE = f'{EXPLANATION}{EXPLANATION_MESSAGE}{BASIC_COLOR}'
NOT_INSTALLED_MESSAGE = '{} is not installed on your system\nYou can install it using pip command:\npip install {}'

# Docker commands.
DOCKER_EXEC_COMMAND = 'sudo docker exec -it {} /bin/{} -c "{}"'
DOCKER_INSPECT_COMMAND = 'sudo docker inspect {}'

# Linux distribution divided by types.
APT_DISTRIBUTIONS = ['Ubuntu', 'Debian']
RPM_DISTRIBUTIONS = ['Red', 'Centos', 'Fedora', 'SUSE', 'SLES', 'Amazon']

# Graphviz.
GRAPH_EXPLOITABLE = 'Exploitable'
GRAPH_NOT_EXPLOITABLE = 'Not Exploitable'
GRAPH_EXPLOITABLE_MESSAGE = 'Exploitable to {}'
GRAPH_NOT_EXPLOITABLE_MESSAGE = 'Not Exploitable to {}'

# Duplicates vulnerabilities names.
DUPLICATE_VULNERABILITIES_NAMES = {'cve_2014_6271': 'shellshock', 'cve_2014_6277': 'shellshock',
                                   'cve_2014_6278': 'shellshock', 'cve_2014_7169': 'shellshock',
                                   'cve_2014_7186': 'shellshock', 'cve_2014_7187': 'shellshock',
                                   'cve_2021_44228': 'log4shell', 'cve_2021_45046': 'log4shell',
                                   'cve_2021_4104': 'log4shell', 'cve_2021_45105': 'log4shell',
                                   'cve_2021_44832': 'log4shell', 'ghost': 'cve_2015_0235',
                                   'dirty_cow': 'cve_2016_5195', 'huge_dirty_cow': 'cve_2017_1000405',
                                   'dirty_pipe': 'cve_2022_0847', 'pwnkit': 'cve_2021_4034',
                                   'spring4shell': 'cve_2022_22965', 'cve_2021_42013': 'cve_2021_41773',
                                   'cve_2022_29799': 'nimbuspwn', 'cve_2022_29800': 'nimbuspwn',
                                   'meltdown': 'cve_2017_5754'}
SPECTRE = ['cve_2017_5715', 'cve_2017_5753', 'cve_2017_5754']

ALL_VULNERABILITIES = ['cve_2015_0235', 'cve_2016_5195', 'cve_2017_5715', 'cve_2017_5753', 'cve_2017_5754',
                       'cve_2017_1000405', 'cve_2021_3177', 'cve_2021_4034', 'cve_2021_41773', 'cve_2022_0847',
                       'cve_2022_22965', 'cve_2022_25636', 'log4shell', 'shellshock', 'nimbuspwn']
