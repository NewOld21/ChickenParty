
from pymongo import MongoClient           # pymongo를 임포트 하기(패키지 인스톨 먼저 해야겠죠?)
from datetime import datetime, timezone
client = MongoClient('localhost', 27017)  # mongoDB는 27017 포트로 돌아갑니다.
db = client.dbjungle  
title_receive = '초밥 같이 먹을 사람'
limit_person_receive = 5  
type_receive = '같이먹기'
category_receive = '일식식'
chat_receive = 'https://www.naver.com/'
note_receive = '짜장면 먹고 싶은데 같이 먹을 사람'
pw_receive = '1234'
invite = {'title' : title_receive, 'limit_person' : limit_person_receive, 'now_person' : 0, 'type_receive' : type_receive, 'category' : category_receive, 'chat' : chat_receive, 'note' : note_receive, 'pw' : pw_receive, "created_at": datetime.now(timezone.utc)}

#db.cp_invites.insert_one(invite)

invite1 = db.cp_invites.find_one({'limit_person' : 5})
print(invite1['created_at'])

#db.cp_invites.update_many({'title': {"$regex": '같이'}},{'$set':{'limit_person':'4'}})

#db.cp_invites.delete_one({'title' : {"$regex" : '초밥'}})