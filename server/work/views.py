from django.shortcuts import get_object_or_404, render_to_response
# Create your views here.
from django.http import HttpResponseRedirect, HttpResponse
from server.work.models import *
import datetime
from django.views.decorators.csrf import csrf_exempt
import logging

logger = logging.getLogger(__name__)

def get_work(request, id):
    task = Task.objects.filter(status="O").all()[0]
    task.status = "IP"
    task.started = datetime.datetime.now()
    task.worker_id = id
    task.save()
    return HttpResponse("\n".join(["%s %d" % (task.bucket, octet) for octet in range(256)]))


@csrf_exempt
def done(request, id):
    if request.method == "POST":
        if not request.POST.has_key("ipblock"):
            return HttpResponse("ERROR: Expecting an ip to be posted to ipblock.")
        ip = " ".join(request.POST["ipblock"].split()[0:3])
        print "ipblock=\"%s\"" % (ip, )
        task = Task.objects.filter(bucket=ip).all()
        if not task:
            logger.error("ERROR: No such ipblock %s" % (ip, ))
            return HttpResponse("ERROR: No such ipblock")
        task = task[0]
        if task.worker_id != id:
            logger.error("ERROR: Invalid worker id")
            return HttpResponse("ERROR: Invalid worker id")
        task.finished = datetime.datetime.now()
        task.status = "F"
        task.save()
        return HttpResponse("OK")

    else:
        return HttpResponse("ERROR: Expecting POST request.")



