from __future__ import absolute_import, division, print_function, unicode_literals
from abc import ABCMeta
import binascii
from collections import OrderedDict
from datetime import date, datetime
import django.utils.formats as formats
import django.utils.html as html
from django.utils.translation import ugettext

#
# Presentable structures
#

class AttributeList(object):
    def __init__(self):
        self._od = OrderedDict()
    
    def append(self, x):
        assert len(x) == 2
        tag = x[0]
        value = x[1]
        assert isinstance(tag, unicode)
        if tag in self._od:
            raise ValueError(b"Attributes must have unique tags")
        if not isinstance(value, Presentable):
            raise ValueError(b"Unrecognized attribute value type")
        self._od[tag] = value
    
    def as_table(self):
        val = "<table>"
        for k, v in self._od.iteritems():
            cell1 = html.escape(ugettext(k))
            cell2 = present(v)
            val += "<tr><th>{0}</th><td>{1}</td></tr>".format(cell1, cell2)
        val += "</table>"
        return val
    
    def find(self, tag, default=None):
        return self._od.get(tag, default)
    
    def __iter__(self):
        return self._od.iteritems()
    
    def __len__(self):
        return len(self._od)

class EntityList(list):
    def __init__(self, column_tags):
        super(EntityList, self).__init__()
        assert isinstance(column_tags, tuple)
        assert len(column_tags) > 0
        assert all((isinstance(e, unicode) for e in column_tags))
        self._ctags = column_tags
    
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
            cell = html.escape(ugettext(v))
            val += "<th>{0}</th>".format(cell)
        val += "</thead><tbody>"
        for v in self:
            val += "<tr>"
            for e in v:
                cell = present(e)
                val += "<td>{0}</td>".format(cell)
            val += "</tr>"
        val += "</tbody></table>"
        return val

#
# Generic object presentation
#

def present_bytes(value):
    hexed = binascii.hexlify(value).decode()
    if len(hexed) <= 40:
        return hexed
    return "<span class=\"longhex\">{0}</span>".format(hexed)

def present_generic(value):
    return html.escape(formats.localize(value))

def present_unicode(value):
    return html.urlize(value, autoescape=True, nofollow=True, trim_url_limit=50)

presenters = {
    AttributeList: AttributeList.as_table,
    bool: present_generic,
    bytes: present_bytes,
    date: present_generic,
    datetime: present_generic,
    EntityList: EntityList.as_table,
    float: present_generic,
    int: present_generic,
    long: present_generic,
    unicode: present_unicode,
    type(None): lambda x: ""
}

class Presentable(object):
    __metaclass__ = ABCMeta

for t in presenters.keys():
    Presentable.register(t)

def present(value):
    for k, v in presenters.iteritems():
        if isinstance(value, k):
            return v(value)
    raise ValueError(b"Value is not presentable")

__all__ = [
    b"AttributeList",
    b"EntityList",
    b"present"
]
