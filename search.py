import pymongo, datetime
from pprint import pprint

connection = pymongo.MongoClient()
db = connection.ssl_all_the_things
certs = db.certs

certs.create_index([ ("pub_key_len", pymongo.ASCENDING), ("subject.CN", pymongo.ASCENDING), ("not_after", pymongo.ASCENDING), ("not_before", pymongo.ASCENDING) ])

today = datetime.datetime.utcnow()
outofdate = {"not_after": {"$lt": today}}
weakkeys = {"pub_key_len": {"$lt": 1024}}

for cert in certs.find(outofdate):
	pprint (cert)