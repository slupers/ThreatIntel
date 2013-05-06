import django.forms as forms
import django.db.models as models
from django.contrib.auth.models import User
from data import *

class UserConfiguration(models.Model):
    user = models.OneToOneField(User, related_name="config", primary_key=True)
    titancert = models.TextField("Titan certificate", blank=True)
    titankey = models.TextField("Titan RSA key", blank=True)
    vtotkey = models.CharField("VirusTotal key", max_length=64, blank=True)
    ptankkey = models.CharField("PhishTank key", max_length=64, blank=True)
    
    def clean(self):
        super(UserConfiguration, self).clean()
        try:
            _mkproviders(self)
        except Exception as e:
            raise forms.ValidationError(e.message)

class UserConfigurationForm(forms.ModelForm):
    class Meta(object):
        model = UserConfiguration
        fields = ("titancert", "titankey", "vtotkey", "ptankkey")

def _mkproviders(config):
    providers = []
    providers.append(DShieldDataProvider())
    providers.append(ShadowServerDataProvider())
    ptankkey = config.ptankkey
    if len(ptankkey) == 0:
        ptankkey = None
    providers.append(PhishTankDataProvider(apikey=ptankkey))
    vtotkey = config.vtotkey
    if len(vtotkey) != 0:
        providers.append(VirusTotalDataProvider(apikey=vtotkey))
    titancert = config.titancert
    titankey = config.titankey
    if len(titancert) != 0 and len(titankey) != 0:
        providers.append(TitanDataProvider(titancert, titankey))
    return providers

def run_query(target, user):
    try:
        config = user.config
    except UserConfiguration.DoesNotExist:
        config = UserConfiguration(user=user)
        config.save()
    providers = _mkproviders(config)
    return DataProvider.queryn(target, providers)
