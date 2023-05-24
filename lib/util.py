from config import DEBUG, LOCATION


def debug(msg: str, loc: str = None):
    if DEBUG:
        if loc is not None:
            if not loc.startswith(LOCATION):
                loc = f'{LOCATION}/{loc}'

            print(f'DEBUG: {loc} | {msg}')

        else:
            print(f'DEBUG: {msg}')
