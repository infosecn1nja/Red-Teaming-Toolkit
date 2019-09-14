#!/usr/bin/env python3
import logging
import os
from argparse import ArgumentParser
from pathlib import Path

from git.repo.base import Repo


class colors:
    BLACK = "\u001b[30m"
    PALE_RED = "\u001b[31m"
    PALE_GREEN = "\u001b[32m"
    PALE_YELLOW = "\u001b[33m"
    PALE_BLUE = "\u001b[34m"
    PALE_MAGENTA = "\u001b[35m"
    PALE_CYAN = "\u001b[36m"

    GRAY = "\u001b[90m"
    RED = "\u001b[91m"
    GREEN = "\u001b[92m"
    YELLOW = "\u001b[93m"
    BLUE = "\u001b[94m"
    MAGENTA = "\u001b[95m"
    CYAN = "\u001b[96m"
    WHITE = "\u001b[97m"

    BG_GRAY = "\u001b[100m"
    BG_RED = "\u001b[41m"
    BG_GREEN = "\u001b[42m"
    BG_YELLOW = "\u001b[43m"
    BG_BLUE = "\u001b[44m"
    BG_MAGENTA = "\u001b[45m"
    BG_CYAN = "\u001b[46m"
    BG_WHITE = "\u001b[47m"

    BOLD = "\u001b[1m"
    RESET = "\u001b[0m"

    @staticmethod
    def colored(text, color=WHITE):
        return f"{color}{text}{colors.RESET}"

    @staticmethod
    def print_colored(text, color=WHITE):
        print(colors.colored(text, color))

    @staticmethod
    def red(text):
        return colors.colored(text, colors.RED)

    @staticmethod
    def green(text):
        return colors.colored(text, colors.GREEN)

    @staticmethod
    def yellow(text):
        return colors.colored(text, colors.YELLOW)

    @staticmethod
    def bold(text):
        return colors.colored(text, colors.BOLD)

    @staticmethod
    def print_red(text):
        colors.print_colored(text, colors.RED)

    @staticmethod
    def print_bold(text):
        print(colors.bold(text))

    @staticmethod
    def print_green(text):
        print(colors.green(text))


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('--search', dest='search', required=False,
                        help='Optional. A query to search within the toolkit.')
    parser.add_argument('--download', dest='download', required=False,
                        help='Optional. Download a tool by it\'s name. The tool will be downloaded in a newly created '
                             'directory. Pass DOWNLOAD_ALL to download everything.')
    parser.add_argument('--show', dest='show', required=False,
                        help='Optional. Show details about the downloaded tool.')
    parser.add_argument('--logging', dest='logging', choices=['INFO', 'DEBUG', 'WARNING', 'ERROR'], default='INFO',
                        help='Optional. Logging level.')
    options = parser.parse_args()

    return options


options = get_arguments()

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=options.logging)

git_sources = [
    'github.com',
    'bitbucket.com'
]


class Tool:
    @staticmethod
    def find_category(url, readme_file):
        with open(readme_file, 'r', encoding='utf-8') as file:
            sections = file.read().split('## ')
            for sec in sections:
                if url in sec:
                    category = sec.split('\n')[0]
                    return {
                        'name': category,
                        'alias': category.lower().replace(' ', '-')
                    }

    @staticmethod
    def fetch_tool_readme(tool_path, tool_name):
        readme_path = str(tool_path) + '/README.md'
        if os.path.exists(readme_path):
            logging.debug('README.md file has been extracted for %s', tool_name)
            return open(readme_path, 'r', encoding='utf-8').read()

    def __init__(self, line, file_content_as_string):
        assert line and line.strip() != ''
        self.name = line.split('**')[1].split('**')[0]
        self.description = line.split('**')[2].split('http')[0].strip()
        self.url = 'http' + line.split('http')[1]
        self.category = self.find_category(self.url, file_content_as_string)
        self.path = Path(os.getcwd() + '/' + self.category['alias'] + '/' + self.name)
        self.tool_readme = self.fetch_tool_readme(str(self.path), self.name) if self.is_downloaded() else None

    def is_downloaded(self):
        return os.path.exists(self.path) and os.listdir(self.path)

    def download(self):
        if self.is_downloaded():
            logging.info('%s is already downloaded', self.name)
            return
        if not any(host in self.url for host in git_sources):
            logging.warning(colors.yellow(
                        'Skipping {} / {} downloading, as it doesn\'t look like a git repository'.format(self.name,
                                                                                                         self.url)))
            return

        logging.info('Downloading %s', self.name)
        self.path.mkdir(parents=True, exist_ok=True)
        try:
            Repo.clone_from(self.url, self.path)
        except Exception as e:
            logging.error(colors.red('Downloading failed: ' + str(e)))
            os.rmdir(self.path)

    def printout(self, verbose=False):
        colors.print_red(colors.bold(self.name) + ' // ' + self.category['name'])
        colors.print_bold(colors.green('DOWNLOADED - ' + colors.RESET + str(self.path)) if self.is_downloaded()
                          else colors.colored('NOT_DOWNLOADED', colors.MAGENTA))
        print(self.url)
        print(self.description)
        if verbose:
            if self.tool_readme:
                print(self.tool_readme)


def download_tool(tool_name, tools):
    for tool in tools:
        if tool.name == tool_name or tool_name == 'DOWNLOAD_ALL':
            tool.download()


def get_tools_from_readme(readme_file):
    tools = []
    with open(readme_file, 'r', encoding='utf-8') as file:
        lines = [line.replace('\n', '') for line in file.readlines()]
        for line in lines:
            if line.startswith('* **'):
                tool = Tool(line, readme_file)
                tools.append(tool)
    return tools


def show_tool_info(tool_name, tools):
    tool_found = False
    for tool in tools:
        if tool_name == tool.name:
            tool_found = True
            tool.printout(True)
    if not tool_found:
        logging.error('Tool %s wasn\'t found', tool_name)


def get_scripts_from_readme(readme_file):
    scripts_url = []
    with open(readme_file, 'r', encoding='utf-8') as file:
        file_content_as_string = [line.replace('\n', '') for line in file.readlines()]
        for line in file_content_as_string:
            if line.startswith('  * '):
                scripts_url.append(line.replace('  * ', ''))
    return scripts_url


def interact(tools):
    prefix = colors.colored('/red-teaming-toolkit:>> ', colors.BG_GRAY)

    def search(command, tools):
        query = command.replace('search ', '')
        search_in_tools(query, tools)

    def download(command, tools):
        tool_name = command.replace('download ', '')
        download_tool(tool_name, tools)

    def show(command, tools):
        tool_name = command.replace('show ', '')
        show_tool_info(tool_name, tools)

    def help():
        print('search <case insensitive query> "search dns"')
        print('download <tool name> "download SharpSploit"/"download DOWNLOAD_ALL"')
        print('show <tool name> "show SharpSploit"')

    while True:
        command = input(prefix)
        if command == 'help' or command == '?':
            help()
        if command.startswith('search '):
            search(command, tools)
        if command.startswith('download '):
            download(command, tools)
        if command.startswith('show '):
            show(command, tools)


def print_categories(tools):
    categories = {}
    for tool in tools:
        category = tool.category['name']
        if category in categories:
            categories[category] += 1
        else:
            categories[category] = 1
    colors.print_bold('Categories statistic:')
    for category, entries in dict([(k, categories[k]) for k in
                                   sorted(categories, key=categories.get, reverse=True)]
                                  ).items():
        if entries > 0:
            colors.print_green(f'{category} - {entries} tool(s)')


def search_in_tools(search, tools):
    logging.info('Searching for %s', search)
    matched_tools = []
    for tool in tools:
        pattern = search.lower()
        if pattern in tool.name.lower() \
                    or pattern in tool.description.lower():
            matched_tools.append(tool)
    matched_tools_count = len(matched_tools)
    logging.info("%s tools found", matched_tools_count)
    if matched_tools_count > 0:
        print_categories(matched_tools)
    for tool in matched_tools:
        tool.printout()
        colors.print_bold('*' * 60)


readme = 'README.md'

scripts = get_scripts_from_readme(readme)
tools = get_tools_from_readme(readme)
downloaded_tools = [t for t in tools if t.is_downloaded()]

logging.info(colors.green('## Red-Teaming-Toolkit initialized'))
logging.info('%s categories discovered', len(set([t.category['alias'] for t in tools])))
logging.info('%s tools synchronized', len(tools))
logging.info('%s tools downloaded', len(downloaded_tools))
logging.info('%s scripts synchronized', len(scripts))

try:
    if options.search:
        search_in_tools(options.search, tools)
    elif options.download:
        download_tool(options.download, tools)
    elif options.show:
        show_tool_info(options.show, tools)
    else:
        interact(tools)
except KeyboardInterrupt:
    logging.info('Keyboard interrupt, exiting')
    exit(0)
except Exception as e:
    logging.error(colors.red('Unexpected error: ' + str(e)))
