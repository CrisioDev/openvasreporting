# Greenbone Reporting:  

[![GitHub version](https://badge.fury.io/gh/TheGroundZero%2Fopenvasreporting.svg)](https://badge.fury.io/gh/TheGroundZero%2Fopenvasreporting)
[![License](https://img.shields.io/github/license/TheGroundZero/openvasreporting.svg)](https://github.com/TheGroundZero/openvasreporting/blob/master/LICENSE)
[![Docs](https://readthedocs.org/projects/openvas-reporting/badge/?version=latest&style=flat)](https://openvas-reporting.sequr.be)
[![Known Vulnerabilities](https://snyk.io/test/github/TheGroundZero/openvasreporting/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/TheGroundZero/openvasreporting?targetFile=requirements.txt)
[![codecov](https://codecov.io/gh/TheGroundZero/openvasreporting/branch/master/graph/badge.svg)](https://codecov.io/gh/TheGroundZero/openvasreporting)
[![Requirements Status](https://requires.io/github/TheGroundZero/openvasreporting/requirements.svg?branch=master)](https://requires.io/github/TheGroundZero/openvasreporting/requirements/?branch=master)
[![PyPI - Version](https://img.shields.io/pypi/v/OpenVAS-Reporting.svg)](https://pypi.org/project/OpenVAS-Reporting/)
[![PyPI - Format](https://img.shields.io/pypi/format/OpenVAS-Reporting.svg)](https://pypi.org/project/OpenVAS-Reporting/)

A tool to convert [Greenbone](https://www.greenbone.net/) XML into reports.

I forked [OpenVAS Reporting](https://github.com/TheGroundZero/openvasreporting) since I had lot of problems with the exported greenbone XMLs. Since we are using the Greenbone Source Edition this is the easiest way for us to create office reports.
Also, OpenVAS mixes their own threat levels with the [CVSS](https://www.first.org/cvss/) scoring, the latter of which I prefer to use in my reports.

## Requirements

 - [Python](https://www.python.org/) version 3
 - [XlsxWriter](https://xlsxwriter.readthedocs.io/)
 - [Python-docx](https://python-docx.readthedocs.io)


## Installation

    # Install Python3 and pip3
    apt(-get) install python3 python3-pip # Debian, Ubuntu
    yum -y install python3 python3-pip    # CentOS
    dnf install python3 python3-pip       # Fedora
    # Clone repo
    git clone https://github.com/TheGroundZero/openvasreporting.git
    # Install required python packages
    cd openvasreporting
    pip3 install -r requirements.txt
    # Install module (not required when running from repo base folder)
    #pip3 install .
    
## Usage

    # When working from the Git repo
    python3 -m openvasreporting -i [OpenVAS xml file(s)] [-o [Output file]] [-f [Output format]] [-l [minimal threat level (n, l, m, h, c)]] [-t [docx template]]

### Parameters

| Short param | Long param | Description     | Required | Default value                              |
| :---------: | :--------- | :-------------- | :------: | :----------------------------------------- |
| -i          | --input    | Input file(s)   | YES      | n/a                                        |
| -o          | --output   | Output filename | No       | openvas_report                             |
| -f          | --format   | Output format   | No       | xlsx                                       |
| -l          | --level    | Minimal level   | No       | n                                          |
| -t          | --template | Docx template   | No       | openvasreporting/src/openvas-template.docx |

## How to

### Export from Greenbone (GVM11)
### Create Excel report from 1 OpenVAS XML report using default settings
    python3 -m openvasreporting -i openvasreport.xml -f xlsx
### Result


### Create Excel report from multiple OpenVAS reports using default settings

    # wildcard select
    python3 -m openvasreporting -i *.xml -f xlsx
    # selective
    python3 -m openvasreporting -i openvasreport1.xml -i openvasreport2.xml -f xlsx

### Create Word report from multiple OpenVAS reports, reporting only threat level high and up, use custom template

    python3 -m openvasreporting -i *.xml -o docxreport -f docx -l h -t "/home/user/myOpenvasTemplate.docx"

## Result

The final report (in Excel format) will then look something like this:

![Report example screenshot - Summary](docs/_static/img/screenshot-report.png?raw=true)
![Report example screenshot - ToC](docs/_static/img/screenshot-report1.png?raw=true)
![Report example screenshot - Vuln desc](docs/_static/img/screenshot-report2.png?raw=true)

Worksheets are sorted according to CVSS score and are colored according to the vulnerability level.

## Ideas

Some of the ideas by GroundZero on which I'm also working:

 - list vulnerabilities per host
 - filter by host (scope/exclude) as in OpenVAS2Report
 - select threat levels individually (e.g. none and low; but not med, high and crit)
