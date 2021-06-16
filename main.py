import pyrebase #Firebase 이용
import requests #자습신청 request를 위한 모듈
import json #Firebase 접속 및 신청 results 해독
import re #로그인 후 화면 html 변환
import os #firebase 인증파일 열기
import progressbar #터미널에 진행바 출력하는 모듈
from cryptography.fernet import Fernet #암호화 모듈
from bs4 import BeautifulSoup #이름, 번호 검증 시 요소 찾기
from datetime import datetime #현재 날짜를 가져오기 위한 모듈

#암호화 키 로딩
with open('./components/key.txt') as f:
    raw_key = f.read()
key = raw_key.encode('utf-8')
cry = Fernet(key)

#파이썬 인증 키 로딩
with open('./components/auth.json') as f:
    config = json.load(f)
firebase = pyrebase.initialize_app(config)
db = firebase.database()

items_to_encrypt = ['id', 'pw']

def encrypt(data):
    if type(data) != bytes:
        if type(data) == str:
            data = data.encode('utf-8')
        if type(data) == int:
            temp = str(data)
    res = cry.encrypt(raw)
    return res.decode('utf-8')

def decrypt(data):
    if type(data) != bytes:
        data = data.encode('utf-8')
    res = cry.decrypt(data)
    return res.decode('utf-8')

def getsitedata(wid, wpw):
    usr_data = {
        'id': wid,
        'password': wpw
    }