import hashpumpy, hashlib
from requests import get, post
host, port = 'crypto.chal.csaw.io', 5003
def new(author, note): return post('http://{}:{}/new'.format(host, port).encode(), data={'author':author, 'note': note}).content.strip().split(' ')[2].split(':')
def view(id, integrity): return post('http://{}:{}/view'.format(host, port), data={'id':id, 'integrity': integrity}).content
secret_length = 13
data = new('asd', 'asd')
sig = hashpumpy.hashpump(data[1], data[0].decode('base64'), '&entrynum=7&admin=True&access_sensitive=True', secret_length)
print (view(sig[1].replace('\x80', '\\x80').replace('\xe0', '\\xe0').encode('base64'), sig[0]))
