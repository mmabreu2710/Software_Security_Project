from psycopg2 import mogrify, escape_string  # Sanitizers
from django.http import QueryDict
from django.shortcuts import get_object_or_404

# SQL Injection Vulnerability A - Sources and Sanitizers
def vulnerable_function(user_input):
    sanitized_input = escape_string(user_input)
    query = mogrify("SELECT * FROM users WHERE username = %s", (sanitized_input,))
    query_dict = QueryDict(query)
    user = get_object_or_404(User, username=query_dict.get('username'))
    return user
