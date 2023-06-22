"""
Support for os and other modules written to avoid repetitive code.
"""
import os
from modules import constants, run_command


def get_file_strings(file, debug):
    """This function returns the file's strings."""
    strings_content = ''
    if check_file_existence(file, debug, container_name=''):
        strings_command = f'strings {file}'
        strings_content = run_command.command_output(strings_command, debug, container_name='')
        strings_content = strings_content.stdout
    return strings_content


def check_file_existence(file_path, debug, container_name):
    """This function checks if the file is exist in the system."""
    exist = False
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        if pipe_cat_file.stdout:
            exist = True
    else:
        if os.path.isfile(file_path):
            exist = True
    return exist


def get_file_content(file_path, debug, container_name):
    """This function returns the file's content if exists."""
    content = ''
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        content = pipe_cat_file.stdout
        if content:
            content = content.split('\n')[: -1]
    else:
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = []
                    for line in file.readlines():
                        content.append(line[: -1])
            except PermissionError:
                cat_file_command = f'sudo cat {file_path}'
                pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
                content = pipe_cat_file.stdout
                if content:
                    content = content.split('\n')[: -1]
    return content
