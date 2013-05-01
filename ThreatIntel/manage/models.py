from django.forms import ModelForm
from django.db import models

class apikeys(models.Model):
	user = models.CharField(max_length=255, primary_key=True)
	titankey = models.CharField(max_length=512)
	icskey = models.CharField(max_length=512)
	dshieldkey = models.CharField(max_length=512)
	cifkey = models.CharField(max_length=512)
	vtotkey = models.CharField(max_length=512)
	ptankkey = models.CharField(max_length=512)
	sserverkey = models.CharField(max_length=512)

class KeysForm(ModelForm):
	class Meta:
		model = apikeys
		fields = ('titankey', 'icskey', 'dshieldkey', 'cifkey', 'vtotkey', 'ptankkey', 'sserverkey' )
	def __init__(self, *args, **kwargs):
		super(KeysForm, self).__init__(*args, **kwargs)
		self.fields['titankey'].required = False
		self.fields['icskey'].required = False
		self.fields['dshieldkey'].required = False
		self.fields['cifkey'].required = False
		self.fields['vtotkey'].required = False
		self.fields['ptankkey'].required = False
		self.fields['sserverkey'].required = False

class qry(models.Model):
	query = models.CharField(max_length=512)
	query_type = models.CharField(max_length=255, choices=[('ipv4','IPv4'),('ipv6','IPv6'),('fqdn','FQDN'),('url','URL'),('hash','Malware hash')])

class QueryForm(ModelForm):
	class Meta:
		model = qry
		fields = ('query', 'query_type')


