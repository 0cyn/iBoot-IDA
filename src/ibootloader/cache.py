#
#  iBootLoader | ibootloader
#  cache.py
#
#  This file handles loading and saving of the cache
#
#  This file is part of iBootLoader. iBootLoader is free software that
#  is made available under the MIT license. Consult the
#  file "LICENSE" that is distributed together with this file
#  for the exact licensing terms.
#
#  Copyright (c) kat 2021.
#

import json
import os
from pathlib import Path


# this is full of potential race conditions and could use a .lock system


class Cache:
    def __init__(self):
        self.cache = None
        self.cache_location = os.path.join(str(Path.home()), '.ibootloader_cache.json')
        self.load_cache()

    def update_latest_filename(self, filename):
        self.load_cache()
        self.cache['latest_file'] = filename
        self.save_cache()

    def latest_filename(self):
        self.load_cache()
        return self.cache['latest_file']

    def cache_keybag(self, keybag, iv, key):
        self.load_cache()
        self.cache['keybags'][keybag] = {'iv': iv, 'key': key}
        self.save_cache()

    def is_keybag_in_cache(self, keybag):
        self.load_cache()
        return keybag in self.cache['keybags']

    def keybag_from_cache(self, keybag):
        return self.cache['keybags'][keybag]

    def load_cache(self):
        if not os.path.exists(self.cache_location):
            self.cache = {'latest_file': '', 'keybags': {}}
            self.save_cache()
        with open(self.cache_location, 'r') as cache_file:
            self.cache = json.load(cache_file)

    def save_cache(self):
        with open(self.cache_location, 'w') as cache_file:
            json.dump(self.cache, cache_file)
