"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, run_command, file_functions

APACHE = 'apache2'
HTTPD = 'httpd'
SERVER_VERSION_FIELD = 'Server version:'
CONFIGURATION_FILE_TYPES = ['/etc/apache2/apache2.conf', '/etc/httpd/conf/httpd.conf', '/etc/apache2/httpd.conf']


def loaded_module(module_line, debug, container_name):
    """This function checks if a given module is loaded."""
    configuration_content = apache_configuration_file(debug, container_name)
    if configuration_content == constants.UNSUPPORTED:
        return constants.UNSUPPORTED
    module_name = module_line.split()[1]
    print(constants.FULL_QUESTION_MESSAGE.format(f'Does Apache HTTP Server load the {module_name} module?'))
    for line in configuration_content:
        if module_line in line:
            line = line.strip()
            if not line.startswith('#') and line.startswith(module_line):
                print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
                print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "{module_name}" module is loaded'))
                return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "{module_name}" module is not loaded'))
    return False


def apache_configuration_file(debug, container_name):
    """This function finds the configuration file path and returns its content if exists."""
    for configuration_file_path in CONFIGURATION_FILE_TYPES:
        configuration_content = file_functions.get_file_content(configuration_file_path, debug, container_name)
        if configuration_content and not 'No such file or directory' in configuration_content[0]:
            return configuration_content
    find_configuration_location_command = f'whereis apache2'
    pipe_apache_configuration = run_command.command_output(find_configuration_location_command, debug, container_name)
    apache_configuration_output = pipe_apache_configuration.stdout
    if not apache_configuration_output or 'not found' in apache_configuration_output:
        return constants.UNSUPPORTED
    configuration_file_paths = apache_configuration_output.split()
    for configuration_file_path in configuration_file_paths:
        configuration_file_types = ['apache2.conf', 'conf/httpd.conf', 'httpd.conf']
        for configuration_file_type in configuration_file_types:
            full_configuration_file_path = f'{configuration_file_path}/{configuration_file_type}'
            configuration_content = file_functions.get_file_content(full_configuration_file_path, debug, container_name)
            if configuration_content and not 'No such file or directory' in configuration_content[0] and not 'Not a directory' in configuration_content[0]:
                return configuration_content
    return constants.UNSUPPORTED


def get_apache_version(apache_output):
    """""This function exports the versions from the output."""
    version = ''
    for field in apache_output.split('\n'):
        if SERVER_VERSION_FIELD in field:
            version = field.split('/')[1].split(' ')[0]
    return version


def check_apache_exists(apache, debug, container_name):
    """""This function perform the check for an Apache HTTP Server existence."""
    apache_command = f'{apache} -v'
    pipe_apache = run_command.command_output(apache_command, debug, container_name)
    apache_output = pipe_apache.stdout
    if not apache_output:
        return ''
    return apache_output


def check_apache_types(debug, container_name):
    """This function checks two types of Apache HTTP Server."""
    print(constants.FULL_QUESTION_MESSAGE.format('Is Apache HTTP Server installed?'))
    apache_output = check_apache_exists(HTTPD, debug, container_name)
    if not apache_output:
        apache_output = check_apache_exists(APACHE, debug, container_name)
        if not apache_output:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server is not installed'))
            return ''
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server is installed'))
    return apache_output
