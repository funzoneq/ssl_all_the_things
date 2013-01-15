from django.core.management.base import BaseCommand, CommandError
from server.work.models import *
from itertools import product


class Command(BaseCommand):
		args = ''
		help = 'Init work database.'

		def handle(self, *args, **options):
				for block in product(range(0, 256), repeat=2):
						# Filter RFC 1918
						#if block[0] == 10: continue
						#if block[0] == 172 and block[1] > 15 and block[1] < 32: continue
						#if block[0] == 192 and block[1] == 168: continue
						#if block[0] == 0: continue
						t = Task(c=block[0], d=block[1])
						t.save()
