from django.forms import ModelForm
from django.db import models
from django.contrib.auth.models import User

class apikeys(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    titancert = models.TextField(blank=True)
    titankey = models.TextField(blank=True)
    cifkey = models.CharField(max_length=36, blank=True)
    vtotkey = models.CharField(max_length=64, blank=True)
    ptankkey = models.CharField(max_length=512, blank=True) # FIXME

class KeysForm(ModelForm):
    class Meta:
        model = apikeys
        fields = ('titancert', 'titankey', 'cifkey', 'vtotkey', 'ptankkey')
    def __init__(self, *args, **kwargs):
        super(KeysForm, self).__init__(*args, **kwargs)
        self.fields['titancert'].required = False
        self.fields['titankey'].required = False
        self.fields['cifkey'].required = False
        self.fields['vtotkey'].required = False
        self.fields['ptankkey'].required = False

class qry(models.Model):
    query = models.CharField(max_length=512)
    #query_type = models.CharField(max_length=255, choices=[('ipv4','IPv4'),('ipv6','IPv6'),('fqdn','FQDN'),('url','URL'),('hash','Malware hash')])

class QueryForm(ModelForm):
    class Meta:
        model = qry
        fields = ('query',)#, 'query_type')
