"""
Support for modules written to avoid repetitive code.
"""
from modules import constants, run_command

APACHE = 'apache2'
HTTPD = 'httpd'
SERVER_VERSION_FIELD = 'Server version:'


def check_apache_modules(apache, debug, container_name):
    """""This function perform the check for an Apache HTTP modules existence."""
    loaded_modules_command = f'{apache} -M'
    pipe_modules = run_command.command_output(loaded_modules_command, debug, container_name)
    modules = pipe_modules.stdout
    if not modules:
        return ''
    return modules


def loaded_modules(module_name, debug, container_name):
    """This function checks if the cgi_module is loaded."""
    print(constants.FULL_QUESTION_MESSAGE.format('Does Apache HTTP Server have loaded modules??'))
    modules = check_apache_modules(APACHE, debug, container_name)
    if not modules:
        modules = check_apache_modules(HTTPD, debug, container_name)
        if not modules:
            print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine loaded modules, unsupported value'))
            return constants.UNSUPPORTED
    if not 'Loaded Modules:' in modules:
        print(constants.FULL_EXPLANATION_MESSAGE.format('Can not determine loaded modules, unsupported value'))
        return constants.UNSUPPORTED
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server has loaded modules'))
    print(constants.FULL_QUESTION_MESSAGE.format(f'Is "{module_name}" module loaded?'))
    if module_name in modules:
        print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
        print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "{module_name}" module is loaded'))
        return True
    print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
    print(constants.FULL_EXPLANATION_MESSAGE.format(f'The "{module_name}" module is not loaded'))
    return False


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
    apache_output = check_apache_exists(APACHE, debug, container_name)
    if not apache_output:
        apache_output = check_apache_exists(HTTPD, debug, container_name)
        if not apache_output:
            print(constants.FULL_POSITIVE_RESULT_MESSAGE.format('No'))
            print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server is not installed'))
            return ''
    print(constants.FULL_NEGATIVE_RESULT_MESSAGE.format('Yes'))
    print(constants.FULL_EXPLANATION_MESSAGE.format('Apache HTTP Server is installed'))
    return apache_output
