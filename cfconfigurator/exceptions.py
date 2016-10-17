#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
python-cfconfigurator is a simple and small library to manage Cloud Foundry
(c) 2016 Jose Riguera Lopez, jose.riguera@springer.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
# Python 2 and 3 compatibility
from __future__ import unicode_literals



class CFException(Exception):
    """Raise for CF exceptions"""

    def __init__(self, response, http_code=400):
        self.description = response.get('description', '')
        self.code = response.get('code', 0)
        self.error_code = response.get('error_code', "CF-Unknown")
        self.http_code = http_code
        message = "%s (%s): %s [%s]" % (self.error_code, self.code, self.description, self.http_code)
        super(CFException, self).__init__(message)

