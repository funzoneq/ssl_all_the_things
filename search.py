import pymongo
from pprint import pprint

connection = pymongo.MongoClient()
db = connection.ssl_all_the_things
collection = db.certs

cert = collection.find_one()

pprint (cert)