"""Bounded local Unix-only smoke of the five synthetic articles; never publishes HTML."""
import http.client
import os
import socket
import stat
import time
from article_test_actions import HeaderResponse
from article_test_host import HostRefused, require, until

PATHS=('/ru/blog/anime-figure-guide','/ru/blog/parcel-packing','/ru/blog/japanese-toothpaste',
       '/ru/blog/how-to-save-on-shipping-goods-from-japan','/blog/uniqlo-airism-clothing-that-cools-you-down')


def request(path,route,deadline):
    until(deadline)
    info=os.stat(path,follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==10001 and stat.S_IMODE(info.st_mode)==0o660,'ARTICLE_INGRESS_REFUSED')
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);response=None
    try:
        connection.settimeout(max(.001,min(2,deadline-time.monotonic())));connection.connect(str(path))
        connection.sendall(('GET '+route+' HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n').encode('ascii'))
        response=HeaderResponse(connection,deadline=deadline);response.begin()
        require(response.getheader('x-robots-tag')=='noindex, nofollow, noarchive'
            and response.getheader('cache-control')=='no-store','ARTICLE_HTTP_REFUSED')
        body=bytearray()
        while not response.isclosed():
            until(deadline);connection.settimeout(max(.001,min(2,deadline-time.monotonic())))
            part=response.read1(min(65536,2*1024**2+1-len(body)))
            if not part:break
            body.extend(part);require(len(body)<=2*1024**2,'ARTICLE_HTTP_REFUSED')
        until(deadline)
        require(info.st_dev==os.stat(path,follow_symlinks=False).st_dev and info.st_ino==os.stat(path,follow_symlinks=False).st_ino)
        return response.status,bytes(body)
    finally:
        if response is not None:response.close()
        connection.close()


def verify(store,deadline):
    path=store.path/'ingress/http.sock';ready=min(deadline,time.monotonic()+45)
    while True:
        try:
            status,body=request(path,PATHS[0],min(ready,time.monotonic()+3))
            require(status==200 and b'<h1' in body,'ARTICLE_HTTP_REFUSED');break
        except Exception:
            require(time.monotonic()+1<ready,'ARTICLE_READINESS_REFUSED');time.sleep(1)
    for route in PATHS[1:]:
        status,body=request(path,route,min(deadline,time.monotonic()+3))
        require(status==200 and b'<h1' in body,'ARTICLE_HTTP_REFUSED')
    for route in ('/article-2760-real-missing','/ru/blog/article-2760-real-missing'):
        status,_=request(path,route,min(deadline,time.monotonic()+3));require(status==404,'ARTICLE_HTTP_REFUSED')
    return {'articles':5,'real_404':2,'visibility':'BASIC_HTML_ONLY','browser_handoff':'CI_ONLY'}
