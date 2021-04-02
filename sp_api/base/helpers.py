from io import BytesIO
from math import ceil

from Crypto.Util.Padding import pad
import hashlib

import base64
from Crypto.Cipher import AES
from ratelimit import limits, RateLimitDecorator


def fill_query_params(query, *args):
    return query.format(*args)


def sp_endpoint(path, method='GET'):
    def decorator(function):
        def wrapper(*args, **kwargs):
            kwargs.update({
                'path': path,
                'method': method
            })
            return function(*args, **kwargs)
        wrapper.__doc__ = function.__doc__
        return wrapper
    return decorator


class SPAPIRateLimitDecorator(RateLimitDecorator):
    """
    Rate limit decorator class for the documented SP-API rate limits.
    """

    def __init__(self, rate: float, raise_on_limit=False):
        """
        Instantiates a RateLimitDecorator decorator. Converts and enforces
        the specified rate limits (per second) to the SP-API.

        Rate limits are documented by Amazon here:
        https://github.com/amzn/selling-partner-api-docs/tree/main/references

        :param float rate: Maximum calls per second as documented by the Amazon documentation. Must be a number greater than 0.
        :param bool raise_on_limit: A boolean allowing the caller to avoiding raising an exception.
        """
        # minimum period required for 2 calls
        period: float = 1 / rate  # in seconds, eg: 120.48

        calls: int = 1 + 1

        super().__init__(calls=calls, period=period, raise_on_limit=raise_on_limit)


rate_limiter = SPAPIRateLimitDecorator  # @rate_limiter


def limiter(rate_per_seconds: float):
    limits()


def encrypt_aes(file_or_bytes_io, key, iv):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    aes = AES.new(key, AES.MODE_CBC, iv)
    try:
        return aes.encrypt(pad(bytes(file_or_bytes_io.read(), encoding='iso-8859-1'), 16))
    except UnicodeEncodeError:
        return aes.encrypt(pad(bytes(file_or_bytes_io.read(), encoding='utf-8'), 16))
    except TypeError:
        return aes.encrypt(pad(file_or_bytes_io.read(), 16))


def decrypt_aes(content, key, iv):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    decrypter = AES.new(key, AES.MODE_CBC, iv)
    decrypted = decrypter.decrypt(content)
    padding_bytes = decrypted[-1]
    return decrypted[:-padding_bytes]


def create_md5(file):
    hash_md5 = hashlib.md5()
    if isinstance(file, BytesIO):
        for chunk in iter(lambda: file.read(4096), b''):
            hash_md5.update(chunk)
        file.seek(0)
        return hash_md5.hexdigest()
    if isinstance(file, str):
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    for chunk in iter(lambda: file.read(4096), b''):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()


def nest_dict(flat: dict()):
    """
    Convert flat dictionary to nested dictionary.

    Input
    {
        "AmazonOrderId":1,
        "ShipFromAddress.Name" : "Seller",
        "ShipFromAddress.AddressLine1": "Street",
    }

    Output
    {
        "AmazonOrderId":1,
        "ShipFromAddress.: {
            "Name" : "Seller",
            "AddressLine1": "Street",
        }
    }


    Args:
        flat:dict():

    Returns:
        nested:dict():
    """

    result = {}
    for k, v in flat.items():
        _nest_dict_rec(k, v, result)
    return result


def _nest_dict_rec(k, v, out):
    k, *rest = k.split('.', 1)
    if rest:
        _nest_dict_rec(rest[0], v, out.setdefault(k, {}))
    else:
        out[k] = v

