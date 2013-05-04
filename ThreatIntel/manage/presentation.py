from __future__ import absolute_import, division, print_function, unicode_literals
import binascii
import django.utils.html

class AttributeList(list):
    def __init__(self):
        super(AttributeSet, self).__init__()
    
    def append(self, x):
        assert len(x) == 2
        tag = x[0]
        value = x[1]
        assert isinstance(tag, unicode)
        assert type(value) in _presenters
        super(AttributeList, self).append((tag, value))
    
    @classmethod
    def _present(cls, value):
        pass

class EntityList(list):
    def __init__(self, column_tags):
        super(EntityList, self).__init__()
        assert len(column_tags) > 0
        assert all((isinstance(e, unicode) for e in column_tags))
        self._ctags = tuple(column_tags)
    
    def append(self, x):
        assert len(x) == len(self._ctags)
        assert all((type(e) in _presenters for e in x))
        super(EntityList, self).append(tuple(x))
        
    @property
    def columns(self):
        return self._ctags
    
    @classmethod
    def _present(cls, value):
        pass

def _present_bytes(value):
    return binascii.hexlify(value).decode()

def _present_date(value):
    pass

def _present_datetime(value):
    pass

def _present_unicode(value):
    return django.utils.html.escape(value)

_presenters = {
    AttributeList: AttributeList._present,
    bytes: _present_bytes,
    date: _present_date,
    datetime: _present_datetime,
    EntityList: EntityList._present,
    unicode: _present_unicode
}
