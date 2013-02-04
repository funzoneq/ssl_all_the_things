import M2Crypto, sys, pymongo, re
import simplejson as json
from datetime import datetime
from pprint import pprint

connection = pymongo.MongoClient()
db = connection.ssl_all_the_things
collection = db.certs
savedcerts = db.extensive
runcount = 0

def failed_cert (id, pem):
	try:
	    f = open("failed/%s.pem" % id, "w")
	    try:
	        f.write(pem) # Write a string to a file
	    finally:
	        f.close()
	except IOError:
	    pass

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

def CN_splitter(subject):
	# transforms issuer = "C=US, O=GTE Corporation, OU=GTE CyberTrust Solutions, Inc., CN=GTE CyberTrust Global Root" into
	# {'C': 'US', 'OU': 'GTE CyberTrust Solutions, Inc.', 'O': 'GTE Corporation', 'CN': 'GTE CyberTrust Global Root'}
	fields = [i.rstrip(", ") for i in re.split(r"([A-Z]{,2})=", subject)][1:]
	return dict( zip( fields[::2], fields[1::2] ) )

for x509 in collection.find():
	json = {}
	json['date'] = x509['date']
	json['endpoint'] = x509['endpoint']
	json['hash'] = x509['hash']
	json['pem'] = x509['pem']
	json['ext'] = {}

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509-module.html
	cert = M2Crypto.X509.load_cert_string(str(x509['pem']))
	#cert = M2Crypto.X509.load_cert('tumblr.pem')

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509.X509-class.html
	try:
		issuer = cert.get_issuer().as_text()
		subject = cert.get_subject().as_text()

		if "," in issuer:
			json['issuer'] = CN_splitter(issuer)

		if "," in subject:
			json['subject'] = CN_splitter(subject)
	except ValueError as e:
		pprint (json)
		pprint (e)
	except NameError as e:
		pprint (json)
		pprint (e)
	except:
		pprint ( cert )
		print "issue/subject: Unexpected error:", sys.exc_info()[0]
		failed_cert (str(x509['_id']), str(x509['pem']))
		pass

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.X509.X509-class.html#get_fingerprint
	json['fingerprint'] = cert.get_fingerprint()

	# http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.RSA.RSA_pub-class.html
	try:
		json['pub_key_len'] = len(cert.get_pubkey().get_rsa())
		json['pub_key'] = cert.get_pubkey().get_rsa().as_pem()
	except:
		print "pub_key: Unexpected error:", sys.exc_info()[0]
		failed_cert (str(x509['_id']), str(x509['pem']))
		break

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

	try:
		cert_id = savedcerts.insert(json)
		runcount += 1
		#print cert_id, json['subject']
	except pymongo.errors.DuplicateKeyError:
		print "DuplicateKeyError:", json
		pass
	except:
		failed_cert (str(x509['_id']), str(x509['pem']))
		print "save: Unexpected error:", sys.exc_info()[0]
		pass
