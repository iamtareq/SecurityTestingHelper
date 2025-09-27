import json

def format_cookies(cookie_string):
    """Format cookie data from a string into a JSON array format."""
    cookies = cookie_string.split('; ')
    formatted_cookies = []

    for cookie in cookies:
        key_value = cookie.split('=')
        if len(key_value) == 2:
            formatted_cookies.append({key_value[0]: key_value[1]})

    return json.dumps(formatted_cookies, indent=4)

# Example usage
if __name__ == "__main__":
    cookie_str = "name1=value1; name2=value2; name3=value3"
    print(format_cookies(cookie_str))
