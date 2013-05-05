import django.forms as forms
import django.db.models as models
from django.contrib.auth.models import User

class UserConfiguration(models.Model):
    user = models.OneToOneField(User, related_name="config", primary_key=True)
    titancert = models.TextField("Titan certificate", blank=True)
    titankey = models.TextField("Titan private key", blank=True)
    cifkey = models.CharField("CIF API key", max_length=36, blank=True)
    vtotkey = models.CharField("VirusTotal API key", max_length=64, blank=True)
    ptankkey = models.CharField("PhishTank API key", max_length=64, blank=True)

class KeysForm(forms.ModelForm):
    class Meta:
        model = UserConfiguration
        fields = ('titancert', 'titankey', 'cifkey', 'vtotkey', 'ptankkey')
    def __init__(self, *args, **kwargs):
        super(KeysForm, self).__init__(*args, **kwargs)
        self.fields['titancert'].required = False
        self.fields['titankey'].required = False
        self.fields['cifkey'].required = False
        self.fields['vtotkey'].required = False
        self.fields['ptankkey'].required = False

class QueryForm(forms.Form):
    query = forms.CharField(min_length=1)
