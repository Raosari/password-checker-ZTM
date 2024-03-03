import requests
import hashlib

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+ query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check api and try again')
    return res


def get_counts_leak(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h,count in hashes:
        if h == hash_to_check: 
            return count
    return 0
    

def pwned_api_check(password):
    '''check if password exist in API response'''
    # print(password.encode('utf-8'))
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char,tail = sha1_password[:5],sha1_password[5:]
    response = request_api_data(first5_char)
    return get_counts_leak(response,tail)


def main(args):
    for password in args:
        count_of_leaks = pwned_api_check(password)
        if count_of_leaks:
            print(f"Your password {password} was found {count_of_leaks} times on internet, you should change it")
        else:
            print(f'Your password \'{password}\' looks secure for now, was not founded on internet leaks')    


if __name__ == '__main__':
    main(['password'])
