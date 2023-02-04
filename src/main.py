import ast
import os.path
import re
import sys
from collections import defaultdict


class CodeAnalyzer:
    errors = {
        "S001": "Too long",
        "S002": "Indentation is not a multiple of four",
        "S003": "Unnecessary semicolon after a statement",
        "S004": "Less than two spaces before inline comments",
        "S005": "TODO found",
        "S006": "More than two blank lines preceding a code line",
        "S007": "Too many spaces after construction_name",
        "S008": "Class name class_name should be written in CamelCase",
        "S009": "Function name function_name should be written in snake_case",
        "S010": "Argument name arg_name should be written in snake_case",
        "S011": "Variable var_name should be written in snake_case",
        "S012": "The default argument value is mutable"
    }

    def __init__(self):
        self.report = None
        self.blank_lines = None
        self.desc_lines = None
        self.file_path = None

    def check_code(self, path: str):
        self.file_path = path
        self.desc_lines = []
        self.blank_lines = 0
        self.report = defaultdict(list)

        # Check rules S010-S012 using an abstract syntax tree
        CodeAnalyzer.check_node(self, self.file_path)

        # Check rules S001-S009 using regular expressions
        with open(self.file_path, "r") as file:
            for line_number, line in enumerate(file.readlines(), start=1):
                # Set the line type
                line_type = CodeAnalyzer.get_line_type(self, line)
                self.desc_lines.append(line_type)
                # Validate line by line for each rule
                CodeAnalyzer.validate_line_length(
                    self, line_number, line, "S001")
                CodeAnalyzer.validate_indentation(
                    self, line_number, line, "S002")
                CodeAnalyzer.validate_semicolon(
                    self, line_number, line, "S003")
                if line_type == "inline_comment":
                    CodeAnalyzer.validate_inline_comments(
                        self, line_number, line, "S004")
                CodeAnalyzer.validate_todo(self, line_number, line, "S005")
                CodeAnalyzer.validate_blank_lines(self, line_number, "S006")
                CodeAnalyzer.validate_blank_lines_after_class(
                    self, line_number, line, "S007")
                CodeAnalyzer.validate_camel_case(
                    self, line_number, line, "S008")
                CodeAnalyzer.validate_snake_case(
                    self, line_number, line, "S009")

        # Print the report of the file analysis
        CodeAnalyzer.print_report(self)

    def get_line_type(self, line: str) -> str:
        # Check line types
        if re.match(r"^\s*$", line):
            self.blank_lines += 1
            return "blank_line"
        elif re.match(r"^\s*#", line):
            return "comment"
        elif re.match(r"^\s*[^#]+#\s*[^#]+", line):
            return "inline_comment"
        else:
            return "code"

    def validate_line_length(self, line_number: int, line: str, error_code: str):
        # Validate line length according to PEP8
        if len(line) > 79:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_indentation(self, line_number: int, line: str, error_code: str):
        # Validate indentation according to PEP8
        if len(re.search(r'^ *', line).group()) % 4 != 0:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_semicolon(self, line_number: int, line: str, error_code: str):
        # Validate semicolon according to PEP8
        if self.desc_lines[line_number - 1] == 'code':
            if re.search(r';$', line):
                CodeAnalyzer.set_report(self, line_number, error_code)
        if self.desc_lines[line_number - 1] == 'inline_comment':
            if re.search(r'.*;.*#', line):
                CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_inline_comments(self, line_number: int, line: str, error_code: str):
        # Validate inline comments according to PEP8
        if self.desc_lines[line_number - 1] == 'inline_comment' and re.search(r' {2}#', line) is None:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_todo(self, line_number: int, line: str, error_code: str):
        # Validate 'TODOs' according to PEP8
        if re.search(r'#.*todo', line, re.IGNORECASE):
            CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_blank_lines(self, line_number: int, error_code: str):
        # Validate blank lines according to PEP8
        if self.desc_lines[line_number - 1] != 'blank_line':
            if self.blank_lines > 2:
                CodeAnalyzer.set_report(self, line_number, error_code)
            self.blank_lines = 0

    def validate_blank_lines_after_class(self, line_number: int, line: str, error_code: str):
        # Validate blank lines after class according to PEP8
        res = re.search(r'^ *(?P<constructor>def|class)(?P<space> *)', line)
        if res is not None and len(res.group('space')) > 1:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_camel_case(self, line_number: int, line: str, error_code: str):
        # Validate camel case according to PEP8
        if re.search(r'^class *', line) and re.search(r'(?P<constructor>class) *[A-Z]([a-zA-Z0-9])*', line) is None:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def validate_snake_case(self, line_number: int, line: str, error_code: str):
        # Validate snake case according to PEP8
        if re.search(r'(^| *)def *', line) and re.search(r'def *[a-z_]{1,2}([a-z0-9_]*_{0,2})', line) is None:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def check_node(self, path: str):
        # This method checks the AST tree for the following rules:
        # S010: Function arguments should be in snake case
        # S011: Variable names should be in snake case
        # S012: Default arguments should be in list
        with open(path, 'r') as f:
            script = f.read()
        tree = ast.parse(script)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    CodeAnalyzer.check_snake_case_node(
                        self, arg.arg, "S010", node.lineno)
                for arg in node.args.defaults:
                    if isinstance(arg, ast.List):
                        CodeAnalyzer.set_report(self, node.lineno, "S012")
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                CodeAnalyzer.check_snake_case_node(
                    self, node.id, "S011", node.lineno)

    def check_snake_case_node(self, name: str, error_code: str, line_number: int):
        # Validate snake case according to PEP8 for AST tree
        if re.search(r'^[a-z_]{1,2}[a-z0-9_]*_{0,2}$', name) is None:
            CodeAnalyzer.set_report(self, line_number, error_code)

    def set_report(self, n_line, error_code):
        # Add error to report
        self.report[n_line].append(error_code)

    def print_report(self):
        # Print report
        for line, _ in self.report.items():
            for error in _:
                print(
                    f"{self.file_path}: Line {line}: {error} {CodeAnalyzer.errors[error]}")


def main(path: str):
    analyzer = CodeAnalyzer()
    list_of_files = []
    if os.path.isfile(path):
        # Check file if a valid path to a file is given
        analyzer.check_code(path)
    else:
        # Walk through all files in the directory
        for dir_path, dir_name, files in os.walk(path, topdown=True):
            for file in files:
                list_of_files.append(os.path.join(dir_path, file))
        # Sort files and check them
        for file in sorted(list_of_files):
            analyzer.check_code(file)


if __name__ == "__main__":
    file_path = sys.argv[1]
    main(file_path)
