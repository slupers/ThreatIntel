from __future__ import absolute_import, division, print_function, unicode_literals
from abc import ABCMeta
from binascii import hexlify
from datetime import date, datetime
from django.utils.formats import localize
from django.utils.html import escape

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
            cell1 = escape(k) # TODO: translate me
            cell2 = present(v)
            val += "<tr><th>{0}</th><td>{1}</td></tr>".format(cell1, cell2)
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
            cell = escape(v) # TODO: translate me
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
# Object presentation
#

def _present_bytes(value):
    return hexlify(value).decode()

def _present_generic(value):
    return escape(localize(value))

def _present_unicode(value):
    return escape(value)

_presenters = {
    AttributeList: AttributeList.as_table,
    bool: _present_generic,
    bytes: _present_bytes,
    date: _present_generic,
    datetime: _present_generic,
    EntityList: EntityList.as_table,
    float: _present_generic,
    int: _present_generic,
    long: _present_generic,
    unicode: _present_unicode
}

class Presentable(object):
    __metaclass__ = ABCMeta

for t in _presenters.keys():
    Presentable.register(t)

def present(value):
    for k, v in _presenters.iteritems():
        if isinstance(value, k):
            return v(value)
    raise ValueError(b"Value is not presentable")

__all__ = [
    b"AttributeList",
    b"EntityList",
    b"Presentable",
    b"present"
]
