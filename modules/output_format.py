"""
Support for csv, json, os and other modules written to avoid repetitive code.
"""
import json
import csv
import os
from modules import constants, file_functions

JSON ='json'
CSV = 'csv'
TEXT = 'text'
DICT_TYPE = 'dict'
STR_TYPE = 'str'
HOST ='host'

def start_of_csv_file(file):
    """This function checks if the file exists, if not - it opens the file in write mode, if yes - opens the file in
    append mode."""
    header = ['vulnerability', 'vulnerable', 'not vulnerable', 'not determined']
    writer = csv.writer(file)
    writer.writerow(header)


def set_csv_line(vulnerability, state):
    """This function creates the lines that will be inserted into the csv file."""
    line = [vulnerability, '0', '0', '0']
    if state == constants.VULNERABLE:
        line[1] = '1'
    elif state == constants.NOT_VULNERABLE:
        line[2] = '1'
    elif state == constants.NOT_DETERMINED:
        line[3] = '1'
    return line


def open_file(container_name, report_format):
    """This function checks if the file exists, if not - it opens the file in write mode, if yes - opens the file in
    append mode."""
    if not os.path.isdir('output'):
        os.mkdir('output')
    if container_name:
        file_name = container_name
    else:
        file_name = HOST
    path = f'output/{file_name}.{report_format}'
    if not file_functions.check_file_existence(path, debug, container_name=''):
        file = open(path, 'w+')
        if report_format == CSV:
            start_of_csv_file(file)
    else:
        file = open(path, 'a')
    return file


def csv_format(container_name, state):
    """This function writes the summary into a csv file."""
    file = open_file(container_name, CSV)
    content = []
    for value in state:
        if DICT_TYPE in str(type(state[value])):
            for pid in state[value]:
                vulnerability = f'{value} - {pid}'
                state_value = state[value][pid]
                content.append(set_csv_line(vulnerability, state_value))
        elif STR_TYPE in str(type(state[value])):
            content.append(set_csv_line(value, state[value]))
    writer = csv.writer(file)
    for line in content:
        writer.writerow(line)
    file.close()


def text_format(container_name, state):
    """This function writes the summary into a text file."""
    file = open_file(container_name, TEXT)
    for value in state:
        if DICT_TYPE in str(type(state[value])):
            file.write(f'{value}\n')
            for pid in state[value]:
                state_value = state[value][pid]
                file.write(f'{pid} : {state_value}\n')
            file.write('\n')
        elif STR_TYPE in str(type(state[value])):
            state_value = state[value]
            line = f'{value} : {state_value}\n\n'
            file.write(line)
    file.close()


def json_format(container_name, state):
    """This function writes the summary into a json file."""
    file = open_file(container_name, JSON)
    json_object = json.dumps(state)
    file.write(json_object)
    file.write('\n\n')
    file.close()


def format_type(container_name, report_format, state):
    """This function checks the format type."""
    if report_format.lower() == JSON:
        json_format(container_name, state)
    elif report_format.lower() == TEXT:
        text_format(container_name, state)
    elif report_format.lower() == CSV:
        csv_format(container_name, state)
    else:
        print('Invalid format value')
        