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

class periodInvalidErr(Exception):
    def __init__(self):
        super().__init__("Period is not valid.")

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

def tidy(string): #2개 이상의 공백 정리
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
    sid = sidchk(''.join(re.findall('\d+', usr_data[:std_pos])))
    
    data = {
        'name': name,
        'sid': sid
    }

    return data

def register(uid_str, data): #data를 uid에 암호화하여 저장
    uid = uid_str

    uidchk = db.child('users').child(uid).get().val()

    if uidchk:
        raise uidAlreadyInUseErr
    
    idchk = db.child('users').get().val()

    for i in idchk:
        comp_id = decrypt(db.child('users').child(i).child('info').child('id').get().val())
        if data['id'] == comp_id:
            raise idAlreadyInUseErr

    for i in ENCRYT_ITEM:
        data[i] = encrypt(data[i])

    db.child('users').child(uid).child('info').set(data)

def register_man(): #프로그램 상에서 수동으로 가입
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
    
    register(uid, usr_data)

    print(' 성공')

def getusrdata(uid_str): #uid의 데이터를 복호화하여 반환
    uid = uid_str

    usr_info = db.child('users').child(uid).child('info').get().val()
    if not usr_info:
        raise noUidFoundErr

    for i in ENCRYT_ITEM:
        usr_info[i] = decrypt(usr_info[i])

    return usr_info

def log_apply(serial, uid, period, clsrm, ctcr, mode): #신청 접수 로그
    timenow = datetime.now().strftime("%Y-%m-%d-%a %H:%M:%S")
    with open('./components/log.txt', "a", encoding='utf-8') as f:
        f.write("\n" + timenow + " - app-" + mode)
        f.write("(" + serial + ")[")
        usr_data = db.child('users').child(uid).child('info').get().val()
        f.write(str(uid) + usr_data['name'] + "(" + str(usr_data['sid']) + ")-")
        f.write(str(period) + "교시," + clsrm + "," + ctcr + "]")

def log_cancel(serial, uid, mode): #신청 취소 로그
    timenow = datetime.now().strftime("%Y-%m-%d-%a %H:%M:%S")
    with open("./components/log.txt", "a", encoding='utf-8') as f:
        f.write("\n" + timenow + " - can-" + mode)
        f.write("(" + serial + ")[")
        usr_data = db.child('users').child(uid).child('info').get().val()
        f.write(str(uid) + usr_data['name'] + "(" + str(usr_data['sid']) + ")]")

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

    tdyapp = gettdyapp(uid)
    
    if not period in tdyapp:
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
            log_apply(result['slrnNo'], uid, period, clsrm, ctcr, "am")
            return result['slrnNo']
        else:
            raise failedApplyingErr

def cancel(uid_str, serial): #자습 신청 취소
    uid = uid_str

    usr_info = getusrdata(uid)

    login_url = 'http://academic.petapop.com/sign/actionLogin.do'
    req_url = 'http://academic.petapop.com/self/deleteSelfLrn.do?slrnNo=' + str(serial)

    usr_data = {
        'id' : usr_info['id'],
        'password' : usr_info['pw']
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
            
        req = sess.post(req_url)
        result = json.loads(req.content.decode('utf8'))

        if result['result']['success']==True:
            log_cancel(serial, uid, 'am')
            return True
        else:
            raise CancelFailErr

def getstat(uid_str): #자습 신청 내용 확인
    uid = uid_str
    usr_info = getusrdata(uid)

    site_data = getsitedata(usr_info['id'], usr_info['pw'])
    find_all = site_data.find_all('tr')

    raw_found = []
    for i in find_all:
        if "교시" in str(i):
            raw_found.append(i)
            
    slflrn_found = []
    for i in raw_found:
        raw_data = str(i)
        i = i.get_text().replace("\n", "")

        pos1 = i.find('교시')
        period = i[pos1-2:pos1-1]

        pos2 = i.find('(')
        clsrm = i[pos1+2:pos2-1]

        pos1 = raw_data.find('deleteSelfLrn')
        pos2 = raw_data.find('" title="신청취소"')
        serial = raw_data[pos1+24:pos2]

        pos = i.find(') 취소')
        grnt_raw = tidy(i[pos+4:])

        if grnt_raw == '미승인':
            granted = False
        elif grnt_raw == '승인':
            granted = True
        elif grnt_raw == '교시 신청':
            continue

        slflrn_found.append({'period': period, 'clsrm': clsrm, 'serial': serial, 'granted': granted})

    return slflrn_found

def gettdyapp(uid_str): #오늘 신청 가능 자습 교시 확인
    uid = uid_str
    usr_info = getusrdata(uid)

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
    
    return slflrn_periods

def gettcrdata(uid_str, period): #해당 자습 교시 신청 가능 교실, 정원 상태, 교사 확인 
    uid = uid_str
    usr_info = getusrdata(uid)
    
    if(type(period) == int):
        period = str(period)

    tdyapp = gettdyapp(uid)

    if not period in tdyapp:
        raise periodInvalidErr

    login_url = 'http://academic.petapop.com/sign/actionLogin.do'
    req_url = 'http://academic.petapop.com/self/writeSelfLrnReqst.do?searchSgnId=20210620&searchLrnPd=' + str(period)

    usr_data = {
        'id' : usr_info['id'],
        'password' : usr_info['pw']
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
            
        req = sess.get(req_url)
        res = req.content.decode('utf-8')

    site_data = BeautifulSoup(res, 'html.parser')

    tcr = {}
    for element in site_data.find_all('option'):
        if element['value']:
            tcr[element.get_text()] = element['value']

    return tcr

def getclsrmdata(uid_str, period, department):
    uid = uid_str
    usr_info = getusrdata(uid)
    
    if(type(period) == int):
        period = str(period)

    tdyapp = gettdyapp(uid)

    if not period in tdyapp:
        raise periodInvalidErr

    login_url = 'http://academic.petapop.com/sign/actionLogin.do'
    req_url = {
        'md' : 'http://academic.petapop.com/clssrm/buldDrw.do?buldId=BUILD_0001&searchSgnId=20210621&searchLrnPd=' + str(period),
        'cd' : 'http://academic.petapop.com/clssrm/buldDrw.do?buldId=BUILD_0002&searchSgnId=20210621&searchLrnPd=' + str(period),
        'ed' : 'http://academic.petapop.com/clssrm/buldDrw.do?buldId=BUILD_0005&searchSgnId=20210621&searchLrnPd=' + str(period)
    }

    usr_data = {
        'id' : usr_info['id'],
        'password' : usr_info['pw']
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
            
        req = sess.get(req_url[department])
        res = req.content.decode('utf-8')

    site_data = BeautifulSoup(res, 'html.parser')

    clsrm = {}

    for element in site_data.find_all('tr'): #하나의 tr 가져와서(이름, id, 정원)
        clsrm_name = 0 #변수들 초기화
        clsrm_tcr = 0
        clsrm_id = 0
        clsrm_max = 0
        clsrm_ppl = 0
        for td in element.find_all('td'): #그 속의 td요소 분석
            ttd = tidy(str(td.get_text())) #내용 정리
            if ttd == '-': #쓸모없는 케이스1
                continue

            elif not ttd: #내용이 비었으면 id긁어오기
                clsrm_id = td.find('div').find('input')['value']
                continue

            elif ttd.isdigit(): #숫자로만 이루어졌으면 continue
                continue

            elif '(' in ttd and ttd[0:1].isdigit(): #정원 관련 내용이면
                std_pos = ttd.find('(')
                clsrm_max = ''.join(re.findall('\d+', ttd[:std_pos]))
                clsrm_ppl = ''.join(re.findall('\d+', ttd[std_pos:]))

            else:
                if not clsrm_name:
                    clsrm_name = ttd
                    continue
                clsrm_tcr = ttd
                continue
        
        #하나의 tr 분석 완료, 해당 내용을 dictionary에 저장
        if (str(clsrm_id)[0:7] != 'CLSSRM_' or '삭제' in str(clsrm_name)):
            continue

        temp = {
            'id' : clsrm_id,
            'max' : clsrm_max,
            'ppl' : clsrm_ppl
        }

        if clsrm_tcr:
            temp['tcr'] = clsrm_tcr

        clsrm[clsrm_name] = temp

        clsrm_tcr = 0
        clsrm_name = 0

    return clsrm

    
data = getclsrmdata('000000', 1, 'md')

for i in data:
    print(i, ":", data[i]['id'] , data[i]['ppl'], data[i]['max'])