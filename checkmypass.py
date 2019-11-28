import requests
import hashlib
import sys

def request_api_data(query_char):  # pass the hashed version of the password, request the data and give a response
    url = 'https://api.pwnedpasswords.com/range/' + query_char   # uses k-anonymity, matches passwords with first 5 characters of hashed password (SHA1)
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError( f'Error fetching: {res.status_code}, check the api and try again')  # raise an error if no status 200
    return res

def get_password_leaks_count(hashes, hash_to_check): # loops through the hash and count, check if any matches (how many times the password has been leaked)
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:  # tail end of the hashed password
            return count  # how many times the password has been leaked
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  #converts the hashed password to a string of double length containing only hexadecimal digits
    first5_char, tail = sha1password[:5], sha1password[5:]  # store the first 5 characters in the first variable, and the reamining characters in the second variable
    response = request_api_data(first5_char)  # call request API data and pass the first 5 characters
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change your password!')
        else:
            print(f'{password} was NOT found, carry on!')
        return 'done'

if __name__ == '__main__':  # only run this file from the command line and not imported in
    sys.exit(main(sys.argv[1:]))  # exit the process and get the return value from main
