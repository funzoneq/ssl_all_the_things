from django.shortcuts import get_object_or_404, render_to_response
# Create your views here.
from django.http import HttpResponseRedirect, HttpResponse
from server.work.models import *
import datetime
from django.views.decorators.csrf import csrf_exempt
import logging
import json
import hashlib
from pymongo import MongoClient

connection = MongoClient()
db = connection.ssl_all_the_things

logger = logging.getLogger(__name__)

def get_work(request):
		task = Task.objects.filter(status="O").all()[0]
		task.status = "IP"
		task.started = datetime.datetime.now()
		task.worker_id = request.META["REMOTE_ADDR"]
		task.save()
		return HttpResponse(json.dumps({"Id": task.id, "C": task.c, "D":task.d}))


def done(request, id):
		task = get_object_or_404(Task, id=id)
		task.status = "F"
		task.finished = datetime.datetime.now()
		task.save()
		return HttpResponse("OK")

@csrf_exempt
def post(request):
		collection = db.certs

		cert = { "endpoint": request.POST["endpoint"],
						 "subject_commonname": request.POST["commonname"],
						 "pem": request.POST["pem"],
						 "hash": hashlib.sha224(request.POST["pem"]).hexdigest(),
						 "date": datetime.datetime.utcnow() }

		cert_id = collection.insert(cert)

		return HttpResponse("OK")

@csrf_exempt
def posthostname(request):
	collection = db.hostnames

	for k,v in request.POST.items():
		if k.startswith("hostname"):
			data = v.split(":")
			hostname = { "hostname": data[0], "ip": data[1] }
			hostname_id = collection.insert(hostname)

	return HttpResponse("OK")