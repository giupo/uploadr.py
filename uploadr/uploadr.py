# -*- coding: utf-8 -*-
#!/usr/bin/env python

"""
   uploadr.py

   Upload images placed within a directory to your Flickr account.

   Requires:
       xmltramp http://www.aaronsw.com/2002/xmltramp/
       flickr account http://flickr.com

   Inspired by:
        http://micampe.it/things/flickruploadr

   Usage:

   Pass the directory and the API key and secret as command line parameters.

   The best way to use this is to just fire this up in the background and forget about it.
   If you find you have CPU/Process limits, then setup a cron job.

   cron entry (runs at the top of every hour )
   0  *  *   *   * /full/path/to/uploadr.py > /dev/null 2>&1

   Februrary 2014
   Momchil Tomov     about.me/tomov

   September 2005
   Cameron Mallory   cmallory/berserk.org

   This code has been updated to use the new Auth API from flickr.

   You may use this code however you see fit in any form whatsoever.

"""

import argparse
import hashlib
import mimetools
import mimetypes
import os
import shelve
import string
import sys
import time
import urllib2
import webbrowser
import random
import datetime

import xmltramp

IMAGE_EXTS = ['jpeg', 'jpg', 'png', 'gif', 'bmp']

#
#   Flickr settings
#
FLICKR = {"title": "",
        "description": "",
        "tags": "auto-upload",
        "is_public": "0",         # DO NOT CHANGE THIS -- OTHERWISE YOUR PHOTOS MIGHT BE EXPOSED FOR THE ENTIRE WORLD TO SEE
        "is_friend": "0",
        "is_family": "0" }

#
#  Filename constants
#
PICTURES_DIRECTORY_MAC = 'Pictures'

UPLOADED_IMAGES_FILENAME = "uploadr.uploaded_images"
CREATED_SETS_FILENAME = "uploadr.created_sets"
CREATED_COLLECTIONS_FILENAME = "uploadr.created_collections"

FAILED_UPLOADS_FILENAME = "uploadr.failed_uploads.log"
IGNORED_FILES_FILENAME = "uploadr.ignored_files.log"

API_KEY_FILENAME = ".uploadr.apiKey"
API_SECRET_FILENAME = ".uploadr.apiSecret"
TOKEN_FILENAME = ".uploadr.flickrToken"


#
#  Flickr API constants
#
FLICKR["api_key"] = None
FLICKR["secret"] = None
FLICKR["max_sets_per_page"] = 500
FLICKR["max_photos_per_page"] = 500


class APIConstants:
    """ APIConstants class
    """

    base = "https://api.flickr.com/services/"
    rest     = base + "rest/"
    auth     = base + "auth/"
    upload   = base + "upload/"
    addToSet = base + ""

    token = "auth_token"
    secret = "secret"
    key = "api_key"
    sig = "api_sig"
    frob = "frob"
    perms = "perms"
    method = "method"

    def __init__( self ):
       """ Constructor
       """
       pass

api = APIConstants()

""" Helpers
"""

def str2key( ss ):
    if not isinstance(ss, unicode):
        s = ss.decode('utf-8')
    else:
        s = ss
    return s.encode("utf-8")

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")


class Uploadr:
    """ Uploadr class
    """

    # API 
    token = None
    perms = ""

    token_file = None
    image_dir = None
    api_key_file = None
    api_secret_file = None
    username = None
    realname = None
    nsid = None

    # Logs
    created_sets = None   # shelve dict, relative path -> id
    created_collections = None  # shelve dict, relative path -> id
    uploaded_images = None # shelve dict, relative path -> id
    failed_uploads = None # text log
    ignored_files = None # text log

    # Stats
    new_sets_count = 0
    new_collections_count = 0
    new_images_count = 0
    failed_sets = dict()
    failed_collections = dict()
    failed_images_count = 0
    skipped_sets = 0
    skipped_collections = 0
    skipped_images_count = 0
    ignored_files_count = 0
    total_files = 0
    total_dirs = 0
    session_info = None


    """     Initialization and Authentication
    """

    def __init__(self, args):
        # get image directory
        if args.dir:
            self.image_dir = args.dir
        else:
            self.image_dir = os.path.join(os.path.expanduser('~'), PICTURES_DIRECTORY_MAC)
        if self.image_dir[-1] != '/':
            self.image_dir += '/'

        # get api key
        self.api_key_file = os.path.join(self.image_dir, API_KEY_FILENAME)
        if args.api_key:
            FLICKR[ api.key ] = args.api_key
        else:
            FLICKR[ api.key ] = self.getCachedAPIKey()
        if not FLICKR[ api.key ]:
            print "API key not found. Please specify your API key using the --api-key parameter."
            sys.exit()

        # get api secret
        self.api_secret_file = os.path.join(self.image_dir, API_SECRET_FILENAME)
        if args.api_secret:
            FLICKR[ api.secret ] = args.api_secret
        else:
            FLICKR[ api.secret ] = self.getCachedAPISecret()
        if not FLICKR[ api.secret ]:
            print "API secret not found. Please specify your API secret using the --api-secret parameter."
            sys.exit()

        # get access token
        self.token_file = os.path.join(self.image_dir, TOKEN_FILENAME)
        self.token = self.getCachedToken()
        if ( not self.checkToken() ):
            self.authenticate()

        # get account info
        self.getInfo()

        # set session info
        now = datetime.datetime.utcnow().strftime("%m/%d%/%Y %H:%M");
        self.session_info = "New upload session started on " + now + \
            "\nDirectory: " + self.image_dir + "" + \
            "\nAccount: " + self.username + " (" + self.realname + ")"


    def signCall( self, data):
        """
        Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
        """
        keys = data.keys()
        keys.sort()
        foo = ""
        for a in keys:
            foo += (a + data[a])

        f = str(FLICKR[ api.secret ]) + api.key + str(FLICKR[ api.key ]) + foo
        #f = api.key + FLICKR[ api.key ] + foo
        return hashlib.md5( f ).hexdigest()

    def urlGen( self , base,data, sig ):
        """ urlGen
        """
        foo = base + "?"
        for d in data:
            foo += d + "=" + data[d] + "&"
        return foo + api.key + "=" + str(FLICKR[ api.key ]) + "&" + api.sig + "=" + sig


    def authenticate( self ):
        """ Authenticate user so we can upload images
        """

        print("Getting new token")
        self.getFrob()
        self.getAuthKey()
        self.getToken()
        self.cacheToken()
        self.cacheAPIKey()
        self.cacheAPISecret()


    def getFrob( self ):
        """
        flickr.auth.getFrob

        Returns a frob to be used during authentication. This method call must be
        signed.

        This method does not require authentication.
        Arguments

        api.key (Required)
        Your API application key. See here for more details.
        """

        d = {
            api.method  : "flickr.auth.getFrob"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            response = self.getResponse( url )
        except:
            print("Error getting frob:" + str( sys.exc_info() ))
            sys.exit()

        if ( self.isGood( response ) ):
            FLICKR[ api.frob ] = str(response.frob)
        else:
            self.reportError( response )
            sys.exit()

    def getAuthKey( self ):
        """
        Checks to see if the user has authenticated this application
        """
        d =  {
            api.frob : FLICKR[ api.frob ],
            api.perms : "write"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.auth, d, sig )
        ans = ""
        try:
            webbrowser.open( url )
            ans = raw_input("Have you authenticated this application? (Y/N): ")
        except:
            print(str(sys.exc_info()))
        if ( ans.lower() == "n" ):
            print("You need to allow this program to access your Flickr site.")
            print("A web browser should pop open with instructions.")
            print("After you have allowed access restart uploadr.py")
            sys.exit()

    def getToken( self ):
        """
        http://www.flickr.com/services/api/flickr.auth.getToken.html

        flickr.auth.getToken

        Returns the auth token for the given frob, if one has been attached. This method call must be signed.
        Authentication

        This method does not require authentication.
        Arguments

        NTC: We need to store the token in a file so we can get it and then check it insted of
        getting a new on all the time.

        api.key (Required)
           Your API application key. See here for more details.
        frob (Required)
           The frob to check.
        """

        d = {
            api.method : "flickr.auth.getToken",
            api.frob : str(FLICKR[ api.frob ])
        }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                self.token = str(res.auth.token)
                self.perms = str(res.auth.perms)
                self.cacheToken()
            else :
                self.reportError( res )
        except:
            print(str(sys.exc_info()))

    def getCachedAPIKey( self ):
        if ( os.path.exists( self.api_key_file )):
            return open( self.api_key_file ).read()
        else :
            return None

    def cacheAPIKey( self ):
        try:
            open( self.api_key_file , "w").write( str(FLICKR[ api.key ]) )
        except:
            print("Issue writing API key to local cache ", str(sys.exc_info()))

    def getCachedAPISecret( self ):
        if ( os.path.exists( self.api_secret_file )):
            return open( self.api_secret_file ).read()
        else :
            return None

    def cacheAPISecret( self ):
        try:
            open( self.api_secret_file , "w").write( str(FLICKR[ api.secret ]) )
        except:
            print("Issue writing API secret to local cache ", str(sys.exc_info()))

    def getCachedToken( self ):
        if ( os.path.exists( self.token_file )):
            return open( self.token_file ).read()
        else :
            return None

    def cacheToken( self ):
        try:
            open( self.token_file , "w").write( str(self.token) )
        except:
            print("Issue writing token to local cache ", str(sys.exc_info()))

    def checkToken( self ):
        """
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        Authentication

        This method does not require authentication.
        Arguments

        api.key (Required)
            Your API application key. See here for more details.
        auth_token (Required)
            The authentication token to check.
        """

        if ( self.token == None ):
            return False
        else :
            d = {
                api.token  :  str(self.token) ,
                api.method :  "flickr.auth.checkToken"
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
            try:
                res = self.getResponse( url )
                if ( self.isGood( res ) ):
                    self.token = res.auth.token
                    self.perms = res.auth.perms
                    return True
                else :
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))
            return False


    """     Crawler
    """

    def prompt(self):
        print "\n---------------------------------------------------------------------------\n"
        print "    This script will examine all files and directories in: " + self.image_dir + ""
        print "    and upload them to Flickr account: " + self.username + " (" + self.realname + ")"
        print "\n---------------------------------------------------------------------------\n"
        return query_yes_no("Are you sure you want to continue?")

    def getHistory( self ):
        self.getCreatedSets()
        self.getCreatedCollections()
        self.getUploadedPhotos()
        self.failed_uploads = open(os.path.join(self.image_dir, FAILED_UPLOADS_FILENAME), 'a')
        self.ignored_files = open(os.path.join(self.image_dir, IGNORED_FILES_FILENAME), 'a')

    def closeHistoryFiles( self ):
        self.created_sets.close()
        self.created_collections.close()
        self.uploaded_images.close()
        self.failed_uploads.close()
        self.ignored_files.close()

    def getSetId( self, relpath, photo_id ):
        p = relpath.split('/')
        set_path = '/'.join(p[:-1])
        if len(p) == 1:
            self.created_sets[str2key(set_path)] = None
        else:
            set_name = p[-2]
            if len(p) == 2:
                collection_name = None
                collection_path = None
            else:
                collection_path = '/'.join(p[:-2])
                collection_name = collection_path

            # create set, optionally
            if not str2key(set_path) in self.created_sets:
                set_id = self.createSet(set_name, photo_id, set_path)
                #  add it to collection
                if collection_name:
                    # create collection, optionally
                    if not str2key(collection_path) in self.created_collections:
                        collection_id = self.createCollection(collection_name, collection_path)
                    else:
                        collection_id = self.created_collections[str2key(collection_path)]
                    self.addSetToCollection(set_id, collection_id)
        return self.created_sets[str2key(set_path)]

    def crawl( self ):
        self.failed_uploads.write('\n' + self.session_info + '\n')
        self.ignored_files.write('\n' + self.session_info + '\n')
        self.skipped_sets = len(self.created_sets)
        self.skipped_collections = len(self.created_collections)

        foo = os.walk(self.image_dir)
        for data in foo:
            (dirpath, dirnames, filenames) = data
            self.total_dirs += 1
            for f in filenames :
                self.total_files += 1
                fullpath = os.path.join(dirpath, f)
                relpath = fullpath[len(self.image_dir):]                
                ext = f.lower().split(".")[-1]
                if ext in IMAGE_EXTS:
                    if not str2key(relpath) in self.uploaded_images:
                        photo_id = self.uploadImage( fullpath, relpath )
                        if photo_id:
                            set_id = self.getSetId(relpath, photo_id)
                            if set_id:
                                self.addImageToSet(photo_id, set_id)
                    else:
                        photoid = self.uploaded_images[str2key(relpath)]
                        print "Skipping image " + relpath + ": already uploaded with id = " + str(photoid)
                        self.skipped_images_count += 1
                else:
                    print 'Ignored file ' + relpath
                    self.ignored_files.write(fullpath + '\n')
                    self.ignored_files_count += 1
                sys.stdout.flush()

    def printStats( self ):
        print "\nCrawling finished!"
        print "Examined " + str(self.total_files) + " files and " + str(self.total_dirs) + " directories"
        print "Uploaded " + str(self.new_images_count) + " images (" \
            + str(self.skipped_images_count) + " images were already uploaded, " \
            + str(self.failed_images_count) + " uploads failed, " \
            + str(self.ignored_files_count) + " files were ignored)" 
        print "Created " + str(self.new_sets_count) + " sets (" \
            + str(self.skipped_sets) + " sets were already created, " \
            + str(len(self.failed_sets)) + " sets failed)"
        print "Created " + str(self.new_collections_count) + " collections (" \
            + str(self.skipped_collections) + " collections were already created, " \
            + str(len(self.failed_collections)) + " collections failed)"
        print ""


    """     API calls
    """

    def getInfo( self ):
        # get user NSID
        try:
            d = {
                api.token          : str(self.token),
                api.perms          : str(self.perms),
                "method"           : "flickr.urls.getUserProfile",
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                self.nsid = str(res[0]('nsid'));
            else :
                self.reportError( res )
                raise
        except:
            print(str(sys.exc_info()))
            sys.exit()
        
        # get username and real name
        try:
            d = {
                api.token          : str(self.token),
                api.perms          : str(self.perms),
                "method"           : "flickr.people.getInfo",
                "user_id"          : self.nsid
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                self.username = res[0][0][0]
                self.realname = res[0][1][0]
            else :
                self.reportError( res )
                raise
        except:
            print(str(sys.exc_info()))
            sys.exit()


    def getCreatedSets( self ):
        self.created_sets_file = os.path.join(self.image_dir, CREATED_SETS_FILENAME)
        self.created_sets = shelve.open(self.created_sets_file)
        if len(self.created_sets) > 0:
            print("\n---------- Loading list of already created sets from file " + self.created_sets_file + " ----------\n")
        else:
            print("\n---------- Getting list of already created sets from Flick account ----------\n")
            page = 1
            while True:
                try:
                    d = {
                        api.token          : str(self.token),
                        api.perms          : str(self.perms),
                        "method"           : "flickr.photosets.getList",
                        "per_page"         : str(FLICKR["max_sets_per_page"]),
                        "page"             : str(page)
                    }
                    page = page + 1
                    sig = self.signCall( d )
                    d[ api.sig ] = sig
                    d[ api.key ] = FLICKR[ api.key ]
                    url = self.build_request(api.rest, d, ())
                    xml = urllib2.urlopen( url ).read()
                    res = xmltramp.parse(xml)
                    if ( self.isGood( res ) ):
                        if len(res[0]) == 0:
                            break
                        for nextset in res[0]:
                            set_name = nextset[0][0]
                            set_path = nextset[1][0]
                            set_id = nextset('id')
                            print '    Existing set ' + set_path + ' (id = ' + str(set_id) + ')'
                            self.created_sets[str2key(set_path)] = set_id
                        success = True
                    else :
                        print("    Problem:")
                        self.reportError( res )
                        raise
                except:
                    print(str(sys.exc_info()))
                    # cleanup
                    self.created_sets.close()
                    os.remove(self.created_sets_file + ".db")
                    sys.exit()

        print '\nLoaded ' + str(len(self.created_sets)) + ' sets!\n\n'

    def getCreatedCollections( self ):
        self.created_collections_file = os.path.join(self.image_dir, CREATED_COLLECTIONS_FILENAME)
        self.created_collections = shelve.open(self.created_collections_file)
        if len(self.created_collections) > 0:
            print("\n---------- Loading list of already created collections from file " + self.created_collections_file + " ----------\n")
        else:
            print("\n---------- Getting list of already created collections from Flickr account ----------\n")
            try:
                d = {
                    api.token          : str(self.token),
                    api.perms          : str(self.perms),
                    "method"           : "flickr.collections.getTree",
                }
                sig = self.signCall( d )
                d[ api.sig ] = sig
                d[ api.key ] = FLICKR[ api.key ]
                url = self.build_request(api.rest, d, ())
                xml = urllib2.urlopen( url ).read()
                res = xmltramp.parse(xml)
                if ( self.isGood( res ) ):
                    for collection in res[0]:
                        collection_name = collection('title')
                        collection_path = unicode(collection('description'))
                        collection_id = collection('id')
                        print '    Existing collection ' + collection_path + ' (id = ' + str(collection_id) + ')'
                        self.created_collections[str2key(collection_path)] = collection_id
                else :
                    print("    Problem:")
                    self.reportError( res )
                    raise
            except:
                print(str(sys.exc_info()))
                # cleanup
                self.created_collections.close()
                os.remove(self.created_collections_file + ".db")
                sys.exit()
        print '\nLoaded ' + str(len(self.created_collections)) + ' collections!\n\n'


    def getUploadedPhotos( self ):
        self.uploaded_images_file = os.path.join(self.image_dir, UPLOADED_IMAGES_FILENAME)
        self.uploaded_images = shelve.open(self.uploaded_images_file)
        if len(self.uploaded_images) > 0:
            print("\n---------- Loading list of already uploaded photos from file " + self.uploaded_images_file + " ----------\n")
        else:
            print("\n---------- Getting list of already uploaded photos from Flickr account ----------\n")
            page = 1
            while True:
                try:
                    d = {
                        api.token          : str(self.token),
                        api.perms          : str(self.perms),
                        "method"           : "flickr.people.getPhotos",
                        "user_id"          : "me",
                        "extras"           : "description",
                        "per_page"         : str(FLICKR["max_photos_per_page"]),
                        "page"             : str(page)
                    }
                    page = page + 1
                    sig = self.signCall( d )
                    d[ api.sig ] = sig
                    d[ api.key ] = FLICKR[ api.key ]
                    url = self.build_request(api.rest, d, ())
                    xml = urllib2.urlopen( url ).read()
                    res = xmltramp.parse(xml)
                    if ( self.isGood( res ) ):
                        if len(res[0]) == 0:
                            break
                        for image in res[0]:
                            image_name = image('title')
                            image_path = image[0][0]
                            image_id = image('id')
                            print '    Existing image ' + image_path + ' (id = ' + str(image_id) + ')'
                            self.uploaded_images[str2key(image_path)] = image_id 
                    else :
                        print("    Problem:")
                        self.reportError( res )
                        raise
                except:
                    print(str(sys.exc_info()))
                    # cleanup
                    self.uploaded_images.close()
                    os.remove(self.uploaded_images_file + ".db")
                    sys.exit()
        print '\nLoaded ' + str(len(self.uploaded_images)) + ' uploaded images!\n\n'            

    def createSet( self, name, image_id , relpath):
        set_id = None;
        print("Creating set " + name + " for directory " + relpath)
        try:
            d = {
                api.token          : str(self.token),
                api.perms          : str(self.perms),
                "method"           : "flickr.photosets.create",
                "title"            : name,
                "description"      : relpath, 
                "primary_photo_id" : str(image_id)
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                set_id = res[0]('id')
                self.created_sets[str2key(relpath)] = set_id
                print("    Success. Set id = " + str(set_id))
                self.new_sets_count += 1
            else :
                print("    Problem:")
                self.reportError( res )
                self.failed_uploads.write('Set: ' + relpath + '\n')
                self.failed_sets[str2key(relpath)] = 1
        except KeyboardInterrupt:
            flick.printStats()
            print "\nUploading session interrupted by user..."
            sys.exit()
        except:
            print(str(sys.exc_info()))
            self.failed_uploads.write('Set: ' + relpath + '\n')
            self.failed_sets[str2key(relpath)] = 1
        return set_id


    def addImageToSet( self, image_id, set_id ):
        success = False
        print("Adding image with id " + str(image_id) + " to set with id " + str(set_id) + "...")
        try:
            d = {
                api.token     : str(self.token),
                api.perms     : str(self.perms),
                "method"      : "flickr.photosets.addPhoto",
                "photoset_id" : str(set_id),
                "photo_id"    : str(image_id)
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                print("    Success.")
                success = True
            else :
                print("    Problem:")
                self.reportError( res )
        except KeyboardInterrupt:
            flick.printStats()
            print "\nUploading session interrupted by user..."
            sys.exit()
        except:
            print(str(sys.exc_info()))
        return success

    def createCollection( self, name, relpath ):
        collection_id = None
        print("Creating collection " + name + " for directory " + relpath)
        try:
            d = {
                api.token          : str(self.token),
                api.perms          : str(self.perms),
                "method"           : "flickr.collections.create",
                "title"            : name,
                "description"      : relpath
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                collection_id = res[0]('id')
                self.created_collections[str2key(relpath)] = collection_id
                print("    Success. Collection id = " + str(collection_id))
                self.new_collections_count += 1
            else :
                print("    Problem:")
                self.failed_uploads.write("Collection: " + relpath + "\n")
                self.reportError( res )
                self.failed_collections[str2key(relpath)] = 1
        except KeyboardInterrupt:
            flick.printStats()
            print "\nUploading session interrupted by user..."
            sys.exit()
        except:
            print(str(sys.exc_info()))
            self.failed_uploads.write("Collection: " + relpath + "\n")
            self.failed_collections[str2key(relpath)] = 1
        return collection_id

    def addSetToCollection( self, set_id , collection_id ):
        success = False
        print("Adding set with id " + str(set_id) + " to collection with id " + str(collection_id) + "...")
        try:
            d = {
                api.token       : str(self.token),
                api.perms       : str(self.perms),
                "method"        : "flickr.collections.addSet",
                "collection_id" : str(collection_id),
                "photoset_id"   : str(set_id)
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                print("    Success.")
                success = True
            else :
                print("    Problem:")
                self.reportError( res )
        except KeyboardInterrupt:
            flick.printStats()
            print "\nUploading session interrupted by user..."
            sys.exit()
        except:
            print(str(sys.exc_info()))
        return success

    def uploadImage( self, image, relpath ):
        photoid = None
        print "Uploading image " + relpath + "..."
        try:
            photo = ('photo', image, open(image,'rb').read())
            d = {
                api.token       : str(self.token),
                api.perms       : str(self.perms),
                "title"         : "",
                "description"   : str( relpath ),
                "tags"          : str( FLICKR["tags"] ),
                "is_public"     : str( FLICKR["is_public"] ),
                "is_friend"     : str( FLICKR["is_friend"] ),
                "is_family"     : str( FLICKR["is_family"] )
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.upload, d, (photo,))
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                photoid = res.photoid
                self.uploaded_images[str2key(relpath)] = photoid
                print("    Success. Image id = " + str(photoid))
                self.new_images_count += 1
            else :
                print("    Problem:")
                self.reportError( res )
                self.failed_uploads.write('Image: ' + relpath + '\n')
                self.failed_images_count += 1
        except KeyboardInterrupt:
            flick.printStats()
            print "\nUploading session interrupted by user..."
            sys.exit()
        except:
            print(str(sys.exc_info()))
            self.failed_uploads.write('Image: ' + relpath + '\n')
            self.failed_images_count += 1
        return photoid 

    def build_request(self, theurl, fields, files, txheaders=None):
        """
        build_request/encode_multipart_formdata code is from www.voidspace.org.uk/atlantibots/pythonutils.html

        Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
        You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        """

        content_type, body = self.encode_multipart_formdata(fields, files)
        if not txheaders: txheaders = {}
        txheaders['Content-type'] = content_type
        txheaders['Content-length'] = str(len(body))

        return urllib2.Request(theurl, body, txheaders)

    def encode_multipart_formdata(self,fields, files, BOUNDARY = '-----'+mimetools.choose_boundary()+'-----'):
        """ Encodes fields and files for uploading.
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return (content_type, body) ready for urllib2.Request instance
        You can optionally pass in a boundary string to use or we'll let mimetools provide one.
        """

        CRLF = '\r\n'
        L = []
        if isinstance(fields, dict):
            fields = fields.items()
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % filetype)
            L.append('')
            L.append(value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY        # XXX what if no files are encoded
        return content_type, body


    def isGood( self, res ):
        """ isGood
        """

        if ( not res == "" and res('stat') == "ok" ):
            return True
        else :
            return False


    def reportError( self, res ):
        """ reportError
        """

        try:
            print("Error: " + str( res.err('code') + " " + res.err('msg') ))
        except:
            print("Error: " + str( res ))

    def getResponse( self, url ):
        """
        Send the url and get a response.  Let errors float up
        """

        xml = urllib2.urlopen( url ).read()
        return xmltramp.parse( xml )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Upload directories to Flickr.')
    parser.add_argument('--dir', action='store', help='Directory with photos to upload')
    parser.add_argument('--api-key', action='store', help="Your Flickr account API key")
    parser.add_argument('--api-secret', action='store',  help="Your Flickr account API secret")
    parser.add_argument('--no-prompt', action='store_true', help="Avoid prompt. Useful for automation.")
    args = parser.parse_args()

    flick = Uploadr(args)
    if args.no_prompt or flick.prompt():
        print '\n' + flick.session_info
        flick.getHistory()
        flick.crawl()
        flick.printStats()
        flick.closeHistoryFiles()
    else:
        print "\nExiting..."
