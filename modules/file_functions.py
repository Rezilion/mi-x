"""
Support for os and other modules which written for avoiding repetitive code.
"""
import os
from modules import constants, run_command


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


def file_content(file_path, debug, container_name):
    """This function checks returns the file's content if exists."""
    content = ''
    if container_name:
        cat_file_command = f'cat {file_path}'
        pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
        content = pipe_cat_file.stdout
        if content:
            content = content.split('\n')[:constants.END]
    else:
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = []
                    for line in file.readlines():
                        content.append(line[:constants.END])
            except PermissionError:
                cat_file_command = f'sudo cat {file_path}'
                pipe_cat_file = run_command.command_output(cat_file_command, debug, container_name)
                content = pipe_cat_file.stdout
                if content:
                    content = content.split('\n')[:constants.END]
    return content
