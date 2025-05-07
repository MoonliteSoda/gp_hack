import os

import yaml
from jinja2 import Template
from enum import Enum

email_template_path = os.path.join(os.path.dirname(__file__), 'email_template.yml')
with open(email_template_path, 'r', encoding='utf-8') as file:
    data = yaml.safe_load(file)

class EmailTemplates(Enum):
    DEFAULT_MESSAGE = Template(data['default'])