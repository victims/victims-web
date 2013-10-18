# This file is part of victims-web.
#
# Copyright (C) 2013 Dulitha Ranatunga
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Search Database
"""

import datetime
import os.path
import re

from flask import (
    Blueprint, current_app, render_template, helpers,
    url_for, request, redirect, flash)
from werkzeug import secure_filename

from flask.ext import login

from victims_web.errors import ValidationError
from victims_web.models import Hash
from victims_web.cache import cache
from flask.ext.mongoengine import Document

from mongoengine.queryset import Q

from mongoengine import (StringField, DateTimeField, DictField,
                         BooleanField)

dbSearch = Blueprint('dbSearch', __name__, template_folder='templates')
# stringFields: Fields which correspond to StringFields in Models.Hash
stringFields = {'name': "", 'version': "", 'format':
                "", 'submitter': "", 'vendor': "", 'cve': ""}
hashFields = {'sha512': "", 'sha256': "", 'md5': ""}
"""
hashFields:
Complex dictionary fields, also stringfields in the end.
Note, only the .combined hash is searched.

Note::
The reason only .combined is searched, is because the schema has this as a
dict field with dynamic key value pairs, it does not seem possible to
dynamically query all key/value pairs in any simple way. A better schema
 would allow for this type of search. If this occurs, look at
Revision: 83b2efe6dd9ba35f60be77ac8d4383e016d55f70 on
https://github.com/pmdematagoda/victims-web/ branch: searchTool
"""

# checkFields: Checkbox fields in html page
checkFields = {'group': {'java': True, 'python': False, 'ruby': False},
               'status': {'submitted': False, 'released': False}}
# dateFields: Date fields in html page
dateFields = {'date_day_val': "", 'date_month_val':
              "", 'date_year_val': ""}
# printFields: fields that are output by html page
printFields = {'name', 'version', 'hashes.sha512.combined'}
# ILLEGAL_CHARACTERS:: any characters that are not allowed in search.
ILLEGAL_CHARACTERS = [',', '/', '\\', '.', '!', '@', '#', '$', '%', '^', '&',
                      '*', '(', ')', '+', '=', '?', '\"', '\'', '<', '>']
unsanitisedMessage = "The following characters are not allowed:"
unsanitisedMessage += "".join(ILLEGAL_CHARACTERS)


def getOrderedStringFields(default=None):
    """Generates the order of each field on the html page,
    currently alphabetical order with 'default' being moved to the top.
    """
    list = stringFields.keys()
    list.extend(hashFields.keys())
    list.sort()
    if default is not None:
        list.remove(default)
        temp = [str(default)]
        temp.extend(list)
        list = temp
    return list


def sanitised(string):
    """Sanitises a string against nosql injection errors.
    Returns 1 if safe, else 0"""
    for c in ILLEGAL_CHARACTERS:
        if c in string:
            return 0
    return 1


def basicSearch(searchField, searchString):
    """Does a basic search of the database, specific to one field at a
    time, any hash searches only checked the combined field."""
    if not sanitised(searchString):
        return (False, "Invalid Input." + unsanitisedMessage, [])

    if len(searchString) == 0:
        return (False, "", [])

    lookup = ""
    field = searchField

    if searchField in hashFields:
        lookup = "hashes__%s__combined__icontains" % searchField
        field = "hashes.%s.combined" % searchField
    elif searchField == 'cve':
        lookup = "cves__id__icontains"
        field = "cves.id"
    else:
        if isinstance(getattr(Hash, searchField), StringField):
            lookup = "%s__icontains" % searchField
        else:
            lookup = searchField

    hashes = Hash.objects().only(field).only(
        *printFields).filter(**{lookup: searchString})

    if (len(hashes) == 0):
        return (False, "No Results Found", [])
    else:
        return (True, str(len(hashes)) + " Results Found", hashes)


def stringQuery(field, searchString, lookup):
    """Advanced search helper function, handles the difference
    between the selected 'contains/exact' boxes

    field = field to be searched
    searchString = string to be searched for
    lookup = existing queryset.
    """
    option = request.form.get(field + "_searchOption", "contains")
    if option == "contains":
        lookup = lookup & Q(**{"%s__icontains" % field: searchString})
    elif option == "exact":
        lookup = lookup & Q(**{"%s__iexact" % field: searchString})
    elif option == "any":
        for term in searchString.split():
            lookup = lookup | Q(**{"%s__icontains" % field: term})

    return lookup


def advancedSearch():
    """
    Queries the database using all the advanced search parameters
    Returns tuple: (Success, Message, Hashes)
        Success- whether the search was succesful, and found items.
        Message- error or success message to be displayed.
        Hashes - Results (Hash objects)
    """

    lookup = Q()

    filterFields = []

    for field in checkFields.keys():
            # Update checkFields
        checkedBoxes = request.form.getlist(field)
        checkedBoxes = [str(x) for x in checkedBoxes]
        checkeredLookup = Q()
        for key in checkFields[field].keys():
            fieldSelected = False
            if key in checkedBoxes:
                checkFields[field][key] = True
                checkeredLookup = checkeredLookup | Q(
                    **{"%s__iexact" % field: key})
                fieldSelected = True
            else:
                checkFields[field][key] = False

            if fieldSelected:
                filterFields.append(field)
        lookup = lookup & checkeredLookup

    # process all the stringField values.
    for field in stringFields.keys():
        # Get and sanitise input
        searchString = str(request.form.get(field + "_searchString", ""))
        if not sanitised(searchString):
            return (False, "Invalid Input for field: " + field +
                    "." + unsanitisedMessage, [])
        stringFields[field] = searchString
        if len(searchString) > 0:
            if field == 'cve':
                field = "cves__id"
            filterFields.append(field)
            lookup = stringQuery(field, searchString, lookup)

    # process all the hash keys
    for field in hashFields.keys():
        # Get and sanitise input
        searchString = str(request.form.get(field + "_searchString", ""))
        if not sanitised(searchString):
            return (False, "Invalid Input for field: " + field +
                    "." + unsanitisedMessage, [])
        hashFields[field] = searchString
        if len(searchString) > 0:
            searchField = "hashes__%s__combined" % field
            lookup = stringQuery(searchField, searchString, lookup)
            filterField = "hashes.%s.combined" % field
            filterFields.append(filterField)

    # process datefield
    day = request.form.get('date_day', "2013")
    month = request.form.get('date_month', "1")
    year = request.form.get('date_year', "1")
    option = request.form.get('date_option', 'on')
    dateFields['date_day_val'] = day
    dateFields['date_month_val'] = month
    dateFields['date_year_val'] = year

    if len(day) > 0 and len(month) > 0 and len(year) > 0:
        filterFields.append('submittedon')
        date = datetime.datetime(int(year), int(month), int(day))
        if option == 'on':
            dateAfter = datetime.datetime(int(year), int(month), int(day) + 1)
            dateLookup = Q(submittedon__gte=date) & Q(
                submittedon__lte=dateAfter)
        elif option == 'before':
            dateLookup = Q(submittedon__lte=date)
        elif option == 'after':
            dateLookup = Q(submittedon__gte=date)
        else:
            dateLookup = Q()

        lookup = lookup & dateLookup

    if len(filterFields) == 0:
        # Nothing to search.
        return (False, "", [])

    # Do the actual search
    hashes = Hash.objects.only(*filterFields).only(*printFields).filter(lookup)

    if (len(hashes) == 0):
        return (False, "No Results Found", [])
    else:
        return (True, str(len(hashes)) + " Results Found", hashes)


def searchPOST(query=None):
    """This function handles the search once some part of the form has been
    submitted"""
    searchField = request.form.get('field', 'name')
    searchString = request.form.get('searchString', '')
    message = "No Results Found"
    success = False

    if 'advSearch' in request.form:
        advanced = "block"

        hashes = []
        success, message, hashes = advancedSearch()
    else:
        advanced = "none"
        success, message, hashes = basicSearch(searchField, searchString)

    data = {
        'advanced': advanced,
        'hashes': hashes,
        'success': success,
        'message': message,
        'basicString': searchString,
        'orderedStringFields': getOrderedStringFields(searchField),
        'stringFields': stringFields,
        'hashFields': hashFields,
        'checkFields': checkFields,
        'dateSearchValues': dateFields
    }
    return render_template('search.html', **data)


def searchGET(query=None):
    """This function handles the display of /search.html when no search query
    has been submitted. (i.e. the default view)"""
    # Reset Fields
    for dict in ['stringFields', 'hashFields', 'dateFields']:
        for key in eval(dict).keys():
            eval(dict)[key] = ""

    for group in checkFields.keys():
        for key in checkFields[group].keys():
            checkFields[group][key] = False

    data = {
        'hashes': [],
        'success': False,
        'message': "",
        'basicString': "",
        'orderedStringFields': getOrderedStringFields(),
        'advanced': "none",
        'stringFields': stringFields,
        'hashFields': hashFields,
        'checkFields': checkFields,
        'dateSearchValues': dateFields

    }
    return render_template('search.html', **data)


@dbSearch.route('/search', methods=['GET', 'POST'])
def search(query=None):
    """This function is highly coupled with search.html.
    The data keys that search.html look for are:

     Used for setting values/defaults:
        hashFields:{field:value}
        checkFields:{field:{option:value}}
        dateSearchValues:{field,value} #Required fields:
                    date_day_val, date_month_val, date_year_val
        orderedStringFields: [<string>]: list of fields that can
            be searched as string. Ordered in alphabetical order,
            with previous selection as first.


     Basic Search::
        basicString:  <string>: previous search string.


     Advanced Search::
       advanced: ["none"|"block"]: whether or not advanced
                                   search is used.

     Results::
        message: <string>: [#results found | error:...| No results found]
        success: <bool>: Whether the search succeeded (and returned >0results)
        hashes: <[objects]>: Hash results from searching.

    """
    if request.method == 'POST':
        return searchPOST()
    else:
        return searchGET()
