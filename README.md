# slflrn-kiosk-CBSH

이 프로젝트는 충북과학고등학교의 사용하기 불편한 자습신청 시스템을 조금이라도 편리하게 하고자,
Python을 활용하여 이 작업을 대신 해 주는 프로그램을 만들기 위함입니다.

장기적으로는 이 코드를 백엔드로써 활용하는 무인기기(KIOSK)를 제작하기 위해서이기도 합니다.

*현재 무인기와 함께 사용 가능한 하이브리드 웹 페이지 제작으로 노선 변경을 논의 중에 있습니다. 추후 결과물이 예상과 달리질 수 있습니다.

**현재 베이스 함수 부분이 완성되었습니다!**

___

# 역할 분담
  
  ## 팀 구성
    - 책임자: enc2586(고1)
    - 구성원: chh1025(고1), appearedherosheep(고1), jaehyeon0832(고1), 도_우(고1)
              #아직 github id를 전달받지 못한 친구들은 부득이하게 실명 작성
    - 기여자: Nebula(선배님)

  ## enc2586
    - 프로젝트 총괄, 비품 관리, 계획 관리
    - 자습신청 웹 사이트 분석
    - 서비스 프로토타입(CLI) 제작
    - 알고리즘의 유지보수 담당 예정(본 사이트의 업데이트에 따른 오류 발생 시)

  ## chh1025
    - 웹 사이트 개발 총괄
    - 웹 프론트엔드 주력 개발
    - 웹 백엔드 기술 팀원들에게 전수
    - 웹 사이트의 유지보수 담당 예정(새로운 디자인, 예기치 못한 오류...)

  ## appearedherosheep
    - 알고리즘 제작 도움
    - 키오스크 본체 디자인 및 제작 담당

  ## jaehyeon0832
    - 엡 백엔드 기술 주력 개발(chh1025로부터 전수)
    - 웹 사이트의 유지보수 담당 예정(chh1025와 함께)

  ## 도*우
    - 피지컬 컴퓨팅 관련 프로그래밍 예정

# 기여 항목

  ● Nebula : 코드 76줄
  
    - 자습신청 사이트의 대략적 구조 분석
    - 자습신청 사이트 로그인과 관련된 대부분의 코드 작성
    - 자습 신청과 관련된 기본적 코드 작성
    - 다른 사용자가 읽기 쉽도록 코드에 주석 작성
    
  ● enc2586 : 코드 560줄(작성만 세면 천 줄 넘음...)
  
    - Nebula님의 코드를 기반으로, 기능을 추가하고 코드를 다듬음:
    - 사용자들의 정보를 데이터베이스로 관리하도록 데이터베이스를 연결함    
    - 웹사이트로부터 학번, 성명을 읽어오는 코드 작성
    - 자습신청 사이트의 자습 신청 구조 분석
    - 자습 신청 취소와 관련된 코드 작성
    - 민감한 정보 암호화/복호화와 관련된 코드 작성
    - 자습신청 사이트의 고유번호 관련 구조 분석
    - 자습신청 기능 이용 시 로그 남기는 코드 작성
    - 어지러운 코드 다듬고 주석 추가
    - 사이트로부터 선생님 목록과 id 받아오는 코드 작성
    - 사이트로부터 교실 현황과 id 받아오는 코드 작성
    - 베이스 함수 부분 모두 혼자 완성(CLI 프로토타입 완성)
