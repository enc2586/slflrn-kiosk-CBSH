import pyrebase #Firebase 이용
import requests #자습신청 request를 위한 모듈
import json #Firebase 접속 및 신청 results 해독
import re #로그인 후 화면 html 변환
import os #firebase 인증파일 열기
import progressbar #터미널에 진행바 출력하는 모듈
from cryptography.fernet import Fernet #암호화 모듈
from bs4 import BeautifulSoup #이름, 번호 검증 시 요소 찾기
from datetime import datetime #현재 날짜를 가져오기 위한 모듈

class loginFailErr(Exception):
    def __init__(self):
        super().__init__("Login attempt failed.")

class sidInvalidErr(Exception):
    def __init__(self):
        super().__init__("sid is invalid.")

class uidAlreadyInUseErr(Exception):
    def __init__(self):
        super().__init__("This uid is already in use.")

class idAlreadyInUseErr(Exception):
    def __init__(self):
        super().__init__(f"This id is already in use.")

class hrmtcrInvalidErr(Exception):
    def __init__(self):
        super().__init__("Retrieved hrmtcr data is invalid.")

class ApplyingFailErr(Exception):
     def __init__(self):
        super().__init__("Login success, but failed to apply.")

class noUidFoundErr(Exception):
    def __init__(self):
        super().__init__("Can't find the uid you requested.")

with open('./components/key.txt') as f: #암호화 키 로드
    raw_key = f.read()
    key = raw_key.encode('utf-8')
    cry = Fernet(key)

with open('./components/auth.json') as f: #파이썬 인증 키 로드
    config = json.load(f)
    firebase = pyrebase.initialize_app(config)
    db = firebase.database()

ENCRYT_ITEM = ['id', 'pw'] #암호화 처리할 것들    

def encrypt(data): #평문 -> 암호문(str)
    if type(data) != bytes:
        if type(data) == str:
            data = data.encode('utf-8')
        if type(data) == int:
            temp = str(data)
    res = cry.encrypt(raw)
    return res.decode('utf-8')

def decrypt(data): #암호문 -> 평문(str)
    if type(data) != bytes:
        data = data.encode('utf-8')
    res = cry.decrypt(data)
    return res.decode('utf-8')

def tidy(string):
    str_lst = string.split()
    string = " ".join(str_lst)

    return string

def getsitedata(wid, wpw): #사이트 긁은 데이터(bs) 반환
    usr_data = {
        'id': wid,
        'password': wpw
    }

    login_url = 'http://academic.petapop.com/sign/actionLogin.do'

    with requests.session() as sess:
        req = sess.post(login_url, data=usr_data)
        res = req.content.decode('utf-8')

    site_data = BeautifulSoup(res, 'html.parser')
    login_chk = tidy(site_data.li.get_text().replace('\n', ''))

    if(login_chk == '선생님은 가입해주세요.'):
        raise loginFailErr
    
    return site_data

def sidchk(sid): #학번 형식 확인, 보정
    if type(sid) != int:
        try:
            sid = int(sid)
        except ValueError:
            raise sidInvalidErr
    
    if sid//1000 == 0:
        num = sid % 10
        sid = sid // 10 * 100 + num

    grade = sid // 1000

    if grade >= 1 and grade <= 3:
        class_ = sid // 100 % 10
        if class_ > 0:
            num = sid % 100
            if num > 0 and num < 30:
                return sid
    
    raise sidInvalidErr

def crlusrdata(wid, wpw): #학번, 이름 반환
    site_data = getsitedata(wid, wpw)
    usr_data = tidy(site_data.li.get_text().replace('\n', ''))

    std_pos = usr_data.find('번')
    name = tidy(usr_data[std_pos+2:std_pos+5])
    sid = sidchk((''.join(re.findall('\d+', usr_data[:std_pos]))))
    
    data = {
        'name': name,
        'sid': sid
    }

    return data

def register_db(uid, data):
    uidchk = db.child('users').child(uid).get().val()

    if uidchk:
        raise uidAlreadyInUseErr
    
    idchk = db.child('users').get().val()

    for i in idchk:
        comp_id = decrypt(db.child('users').child(i).child('info').child('id').get().val())
        if data['id'] == comp_id:
            raise idAlreadyInUseErr

    db.child('users').child(uid).child('info').set(data)

def register_man():
    while True:
        uid = input("uid: ")

        uidchk = db.child('users').child(uid).get().val()

        try:
            if uidchk:
                raise uidAlreadyInUseErr
        except uidAlreadyInUseErr:
            print("해당 uid는 이미 사용중입니다. 다시 시도하세요.")
            continue

        break

    usr_data = {'ud': datetime.today().year}

    while True:
        usr_data['id'] = str(input('id: '))
        usr_data['pw'] = str(input('pw: '))

        print('첫 로그인 진행...', end='')

        try:
            usr_info = crlusrdata(usr_data['id'], usr_data['pw'])
        except loginFailErr:
            print('\n해당 id와 pw로 로그인에 실패했습니다. 다시 시도하세요.')
            continue

        break

    print(' 성공')

    usr_data['name'] = usr_info['name']
    usr_data['sid'] = usr_info['sid']

    print('정보를 자동으로 감지했습니다.')
    print('아래 정보가 맞으면 Enter, 아니면 n을 입력해주세요.')
    print('이름: ' + usr_data['name'])
    print('학번: ' + str(usr_data['sid']))

    data_approval = input()

    if data_approval == 'n':
        print('정보 수정 모드')
        usr_data['name'] = input('이름: ')
        usr_data['sid'] = input('학번: ')

    print('정보에 대해 사용자의 승인을 받았습니다.')

    print('민감 정보 암호화 후 데이터베이스 등록 시도...', end='')
    
    register_db(uid, usr_data)

    print(' 성공')

def getusrdata(uid):
    usr_info = db.child('users').child(uid).child('info').get().val()
    if not usr_info:
        raise noUidFoundErr

    for i in ENCRYT_ITEM:
        usr_info[i] = decrypt(usr_info[i])

    return usr_info

def apply_man():
    print("hello")

def apply(uid_str, period, clsrm, ctcr): #자습 등록

    uid = uid_str

    if(type(period) == int):
        period = str(period)

    usr_info = getusrdata(uid) #정보 복호화

    try: #소속 반 인식
        usr_class = int(usr_info['sid']) // 100
        if(usr_class <= 10 or usr_class >= 40):
            raise sidInvalidErr
    except ValueError:
        raise sidInvalidErr

    hrmtcr = db.child('hrmtcr').child(str(usr_class)).get().val() #담임교사 가져옴
    if not hrmtcr:
        raise hrmtcrInvalidErr

    site_data = getsitedata(usr_info['id'], usr_info['pw'])
    find_all = site_data.find_all('tr')

    raw_found = []

    for i in find_all:
        if "교시" in str(i):
            raw_found.append(i)

    slflrn_periods = []

    for i in raw_found:

        raw_data = str(i)
        i = i.get_text().replace("\n", "")

        pos1 = i.find('교시')
        period_str = i[pos1-2:pos1-1]

        slflrn_periods.append(period_str)
    
    if not period in slflrn_periods:
        raise periodInvalidErr
    
    clsrmid = db.child('clsrm').child(clsrm).get().val()
    hrmtcrid = db.child('tcr').child(hrmtcr).get().val()
    ctcrid = db.child('tcr').child(ctcr).get().val()

    form_data = {
        'clssrmId':clsrmid, #장소
        'roomTcherId':hrmtcrid, #담임교사(homeRoomTeahcer)
        'cchTcherId':ctcrid #지도교사(RequestedRoomTeacher)
    }

    login_url = 'http://academic.petapop.com/sign/actionLogin.do'
    req_url = 'http://academic.petapop.com/self/requestSelfLrn.do?sgnId=' + datetime.now().strftime("%Y%m%d") + '&lrnPd=' + period

    usr_data = {
        'id': usr_info['id'],
        'password': usr_info['pw']
    }

    with requests.session() as sess:
        #로그인
        res = sess.post(login_url, data=usr_data)
        login_data = res.content.decode('utf8')
        usr_data = tidy(BeautifulSoup(login_data, "html.parser").li.get_text().replace("\n", ""))
    
        std_pos = usr_data.find('번')
        name_crwl = tidy(usr_data[std_pos+2:std_pos+5])

        if(name_crwl != usr_info['name']):
            raise loginFailErr

        req = sess.post(req_url, data=form_data)
        result = json.loads(req.content.decode('utf8'))

        if result['result']['success']==True:
            return result['slrnNo']
        else:
            raise failedApplyingErr
        
print(apply('000000', 4, '합동강의실', '감독교사'))

#today = datetime.now().strftime("%Y%m%d")