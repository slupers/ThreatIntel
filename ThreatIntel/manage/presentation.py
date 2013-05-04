from __future__ import absolute_import, division, print_function, unicode_literals
import abc
import binascii
import datetime
import django.utils.formats
import django.utils.html

#
# Presentable structures
#

class AttributeList(list):
    def __init__(self):
        super(AttributeSet, self).__init__()
    
    def append(self, x):
        assert len(x) == 2
        tag = x[0]
        value = x[1]
        assert isinstance(tag, unicode)
        assert isinstance(value, Presentable)
        super(AttributeList, self).append((tag, value))
    
    def as_table(self):
        val = "<table>"
        for k, v in self:
            c1 = django.utils.html.escape(k) # TODO: translate me
            c2 = django.utils.html.escape(v)
            val += "<tr><th>{0}</th><td>{1}</td></tr>".format(c1, c2)
        val += "</table>"
        return val

class EntityList(list):
    def __init__(self, column_tags):
        super(EntityList, self).__init__()
        assert len(column_tags) > 0
        assert all((isinstance(e, unicode) for e in column_tags))
        self._ctags = tuple(column_tags)
    
    def append(self, x):
        assert len(x) == len(self._ctags)
        assert all((isinstance(e, Presentable) for e in x))
        super(EntityList, self).append(tuple(x))
        
    @property
    def columns(self):
        return self._ctags
        
    def as_table(self):
        val = "<table><thead>"
        for v in self._ctags:
            c = django.utils.html.escape(v) # TODO: translate me
            val += "<th>{0}</th>".format(c)
        val += "</thead><tbody>"
        for v in self:
            val += "<tr>"
            for e in v:
                c = django.utils.html.escape(e)
                val += "<td>{0}</td>".format(c)
            val += "</tr>"
        val += "</tbody></table>"
        return val

#
# Object presentation
#

def _present_bytes(value):
    return binascii.hexlify(value).decode()

def _present_generic(value):
    return django.utils.html.escape(django.utils.formats.localize(value))

def _present_unicode(value):
    return django.utils.html.escape(value)

_presenters = {
    AttributeList: AttributeList.as_table,
    bool: _present_generic,
    bytes: _present_bytes,
    datetime.date: _present_generic,
    datetime.datetime: _present_generic,
    EntityList: EntityList.as_table,
    float: _present_generic,
    int: _present_generic,
    long: _present_generic,
    unicode: _present_unicode
}

class Presentable(object):
    __metaclass__ = abc.ABCMeta

for t in _presenters.keys():
    Presentable.register(t)
