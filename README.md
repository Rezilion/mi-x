[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![pylint](https://user-images.githubusercontent.com/15197376/178207178-872a404a-a3c0-4442-b0ce-94a76e38848a.svg)

<p align="center">
<img src="https://user-images.githubusercontent.com/15197376/178677447-74914a41-4664-47af-b156-9022f094bfbb.png#center" width="400" height="200" />
</p>

# **Am I Exploitable?**

 Author:                   2022 - Now, Rezilion

 Description:              Vulnerabilities validation

 Development:              January 2022 - Now

 Documentation:            See website, README


# Introduction

## Description
‘Am I Exploitable?’ is a python open source project that comes to meet the need of validating if your system is exploitable to specific vulnerabilities.
The project can help you understand whether you are exploitable to a specific vulnerability and explain to you what is the vulnerable component or invulnerable component in your system.
The project can create a graph that presents the validation flow according to the vulnerability checks we perform.
We want to create a community of researchers and programmers that can add vulnerability checks for new vulnerabilities or critical or famous vulnerabilities. Whenever a new vulnerability comes up, we can offer this service that helps people validate if they are exploitable or not.
In addition, the vulnerabilities checks we wrote so far, can be expanded with some checks we might have missed.

## Features and usage options:
* Validate if exploitable to provided cve
* Validate if exploitable to category of cves
* Get the vulnerability description
* Validate the host containers
* Present the validation flow logic as a graph. 

An example flow graph for CVE-2021-4034 (aka PwnKit):

![PWNKIT_Flow](https://user-images.githubusercontent.com/15197376/165183294-45482743-1c92-4b24-8477-812a62537c71.png)

Everyone is free to use 'Am I Exploitable?' under the conditions of the AGPL-3.0 License (see [LICENSE](https://github.com/Rezilion/mi-x/blob/main/LICENSE) file).
 
## Quick facts
   - **Name**:      'Am I Exploitable?'
   - **Type**:      vulnerability validation
   - **License**:   GNU AFFERO GENERAL PUBLIC LICENSE
   - **Language**:  Python3
   - **Author**:    Rezilion
   - **Required Permissions**: root preferred, not needed (may use sudo)
   
# Files

- `am_i_exploitable.py` - The main file which handles the user input and the CVEs calls.
- `CVEs` - Python package that contains a python file for each currently supported CVE.
- `Modules` - Python package that contains modules.
Modules are code implementations which are used in different CVE files.


# Support Distributions

The tool supports the following Linux distributions:

Ubuntu, Debian, Red Hat, Centos, Fedora, SUSE, SLES, Amazon

Partial support for Alpine


# Color Legend

<img width="341" alt="colors" src="https://user-images.githubusercontent.com/104366208/165800276-f31d063b-f031-4569-8f61-72832c602031.png">

# Installation Requirements

1. Python version 3
2. Graphviz (optional, needed only for the graph capabilities) 
3. Xdg-utils (optional, needed only for the graph capabilities)
4. openjdk with jcmd support (needed when running in container mode and the openjdk version on the container is lower than `openjdk10`)

In order to install the requirements:
1. Check your os distribution you can use the following command:
   ```
   cat /etc/os-release
   ```
2. Understand which package manager your os distribution is using:

   apt - Ubuntu, Debian
   
   yum - Red Hat, CentOS, Fedora, SUSE, SLES, Amazon
3. Install the relevant package using your os distribution package manager
4. Install the relevant package using your os distribution package manager

# Dependencies Installation
- graphviz
```
pip install -r requirements.txt
```

# Installation

The very latest developments can be obtained via git.

Clone or download the project files (no compilation nor installation is required) 
```
git clone https://github.com/Rezilion/mi-x.git
```
Execute:
```
cd mi-x && python3 am_i_exploitable.py
```
# Execution Example

Execute the program using parameters
```
python3 am_i_exploitable.py --cve_id cve_yyyy_xxxx --container True --graph True
```
![Executing](https://user-images.githubusercontent.com/15197376/178207295-d1a5f251-063d-406d-8821-c7a7d6d4c39b.gif)


# Arguments

## --cve_id

Specifies the CVE ID that will be checked. 

Syntax: 
- all - runs all the vulnerabilities in the CVEs directory
- cve_year_id - runs specific cve by the vulnerability cve id
- name - runs specific cve by the vulnerability name

If the argument is not set, a menu message will appear presenting the currently supported vulnerabilities.

## --container

The user needs to specify whether to examine running containers on the host (False by default).
- When running with containers, the user will need to insert the user’s password for sudo use.

## --describe

The user needs to specify whether to see the CVE description or not (True by default).

## --graph

The user needs to specify whether to see the validation flow chart (False by default).

## --help

Help to understand how to run the code

# Supported Systems

'Am I Exploitable?' currently supports Linux.

This tool is tested or confirmed to work with Linux systems.

# Development and Bugs

Found an issue, or have a great idea? Let us know:

* GitHub - https://github.com/Rezilion/mi-x.git
* E-mail - ofrio@rezilion.com

Contributions are appreciated and can be done via GitHub. 

See CONTRIBUTING.md for more information about how to submit them.

# Support

'Am I Exploitable?' is tested on most common Linux operating systems. The documentation (README) and the debugging 
information (set the debug parameter to 'True'), should cover most questions and problems. 

Bugs can be reported via GitHub, or sending an e-mail to the email address above.

# Thanks

Thanks to the community for using and supporting open source software.

Many comments, bugs/patches and questions are the key to success and ongoing motivation in developing tools like this.
