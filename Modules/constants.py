# Colors.
BASIC_COLOR = '\033[00m'
NOT_VULNERABLE = '\033[102m'
VULNERABLE = '\033[101m'
QUESTION = '\033[94m'
POSITIVE_RESULT = '\033[92m'
NEGATIVE_RESULT = '\033[91m'
NEUTRAL_RESULT = '\033[93m'
EXPLANATION = '\033[90m'

# Return value.
UNSUPPORTED = 'Unsupported'

# List indexes.
START = 0
FIRST = 1
END = -1

# Messages.
NOT_VULNERABLE_MESSAGE = 'Your system is not vulnerable to {}'
PROCESS_NOT_VULNERABLE_MESSAGE = '{} process is not vulnerable to {}'
VULNERABLE_MESSAGE = 'Your system is vulnerable to {}'
PROCESS_VULNERABLE_MESSAGE = '{} process is vulnerable to {}'
QUESTION_MESSAGE = '{}'
NEUTRAL_RESULT_MESSAGE = '{}'
EXPLANATION_MESSAGE = '{}'
FULL_NOT_VULNERABLE_MESSAGE = f'{NOT_VULNERABLE}{NOT_VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_NOT_VULNERABLE_MESSAGE = f'{NOT_VULNERABLE}{PROCESS_NOT_VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_VULNERABLE_MESSAGE = f'{VULNERABLE}{VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_PROCESS_VULNERABLE_MESSAGE = f'{VULNERABLE}{PROCESS_VULNERABLE_MESSAGE}{BASIC_COLOR}'
FULL_QUESTION_MESSAGE = f'{QUESTION}{QUESTION_MESSAGE}{BASIC_COLOR}'
FULL_NEGATIVE_RESULT_MESSAGE = f'{NEGATIVE_RESULT}Yes{BASIC_COLOR}'
FULL_POSITIVE_RESULT_MESSAGE = f'{POSITIVE_RESULT}No{BASIC_COLOR}'
FULL_NEUTRAL_RESULT_MESSAGE = f'{NEUTRAL_RESULT}{NEUTRAL_RESULT_MESSAGE}{BASIC_COLOR}'
FULL_EXPLANATION_MESSAGE = f'{EXPLANATION}{EXPLANATION_MESSAGE}{BASIC_COLOR}'
FULL_UNSUPPORTED_MESSAGE = f'{BASIC_COLOR}One of the checks went wrong.. exit the program\nFor details execute in ' \
                           f'debug mode{BASIC_COLOR}'

# Docker commands.
DOCKER_EXEC_COMMAND = 'sudo docker exec -it {} /bin/{} -c "{}"'
DOCKER_INSPECT_COMMAND = 'sudo docker inspect {}'

# Linux distribution divided by types.
APT_DISTRIBUTIONS = ['Ubuntu', 'Debian']
RPM_DISTRIBUTIONS = ['Red', 'Centos', 'Fedora', 'SUSE', 'SLES']

# Graphviz.
GRAPHVIZ_NOT_INSTALLED = 'Graphviz is not installed on your system'
GRAPH_VULNERABLE = 'Vulnerable'
GRAPH_NOT_VULNERABLE = 'Not Vulnerable'
GRAPH_VULNERABLE_MESSAGE = 'Vulnerable to {}'
GRAPH_NOT_VULNERABLE_MESSAGE = 'Not Vulnerable to {}'

# Duplicates vulnerabilities names.
DUPLICATE_VULNERABILITIES_NAMES = {'cve_2014_6271': 'shellshock', 'cve_2014_6277': 'shellshock',
                                   'cve_2014_6278': 'shellshock', 'cve_2014_7169': 'shellshock',
                                   'cve_2014_7186': 'shellshock', 'cve_2014_7187': 'shellshock',
                                   'cve_2021_44228': 'log4shell', 'cve_2021_45046': 'log4shell',
                                   'cve_2021_4104': 'log4shell', 'cve_2021_45105': 'log4shell',
                                   'cve_2021_44832': 'log4shell', 'dirty_cow': 'cve_2016_5195',
                                   'huge_dirty_cow': 'cve_2017_1000405', 'dirty_pipe': 'cve_2022_0847',
                                   'pwnkit': 'cve_2021_4034', 'spring4shell': 'cve_2022_22965',
                                   'cve_2021_42013': 'cve_2021_41773'}

ALL_VULNERABILITIES = ['cve_2015_0235', 'cve_2016_5195', 'cve_2017_1000405', 'cve_2021_3177', 'cve_2021_4034',
                       'cve_2021_41773', 'cve_2022_0847', 'cve_2022_22965', 'cve_2022_25636', 'log4shell', 'shellshock']