''' initiate django shizzle '''
from django.core.management import setup_environ
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import server.settings

setup_environ(server.settings)

from django.db import models
from server.work.models import Certificate

import M2Crypto
import pprint
import pymongo
import simplejson as json
from datetime import datetime

connection = pymongo.MongoClient()
db = connection.ssl_all_the_things
collection = db.certs
json = {}
json['ext'] = {}

def split_ext(ext):
	try:
		save = []
		for k in ext:
			l = k.split(", ")
			for m in l:
				save.append(m.strip().split(":"))
		return save
	except:
		pass

for x509 in Certificate.objects.raw("SELECT * FROM work_certificate LIMIT 500000, 100000"):
	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509-module.html
	cert = M2Crypto.X509.load_cert_string(str(x509.pem))
	#cert = M2Crypto.X509.load_cert('tumblr.pem')

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509.X509-class.html
	try:
		json['issuer'] = cert.get_issuer().as_text()
		json['subject'] = cert.get_subject().as_text()

		if "," in json['issuer']:
			json['issuer'] = json['issuer'].split(", ")

		if "," in json['subject']:
			json['subject'] = json['subject'].split(", ")
	except:
		pass

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509.X509-class.html#get_fingerprint
	json['fingerprint'] = cert.get_fingerprint()

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.RSA.RSA_pub-class.html
	json['pub_key_len'] = len(cert.get_pubkey().get_rsa())
	json['pub_key'] = cert.get_pubkey().get_rsa().as_pem()

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.ASN1.ASN1_UTCTIME-class.html
	try:
		json['not_before'] = cert.get_not_before().get_datetime()
		json['not_after'] = cert.get_not_after().get_datetime()
	except:
		json['not_before'] = datetime(1970, 1, 1, 0, 0, 0)
		json['not_after'] = datetime(1970, 1, 1, 0, 0, 0)

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509.X509_Extension-class.html
	count = cert.get_ext_count()
	for i in range(0, count):
		try:
			value = cert.get_ext_at(i).get_value().strip().split("\n")
		except:
			value = ""
		key = cert.get_ext_at(i).get_name()

		if key == "subjectAltName" or key == "basicConstraints":
			value = split_ext(value)

		json['ext'][key] = value

	print json['subject']
	try:
		cert_id = collection.insert(json)
		print cert_id
	except pymongo.errors.DuplicateKeyError:
		pass
	except:
		pass
