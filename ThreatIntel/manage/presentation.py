from __future__ import absolute_import, division, print_function, unicode_literals
import abc
import binascii
from datetime import date, datetime
import django.utils.formats as formats
import django.utils.html as html
from django.utils.translation import ugettext, get_language_info

#
# Presentable structures
#

class AttributeList(list):
    def __init__(self):
        super(AttributeList, self).__init__()
    
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
            cell1 = html.escape(ugettext(k))
            cell2 = present(v)
            val += "<tr><th>{0}</th><td>{1}</td></tr>".format(cell1, cell2)
        val += "</table>"
        return val

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
    return binascii.hexlify(value).decode()

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
    __metaclass__ = abc.ABCMeta

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
