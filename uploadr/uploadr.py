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

   The best way to use this is to just fire this up in the background and forget about it.
   If you find you have CPU/Process limits, then setup a cron job.

   %nohup python uploadr.py -d &

   cron entry (runs at the top of every hour )
   0  *  *   *   * /full/path/to/uploadr.py > /dev/null 2>&1

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
import xmltramp

#
##
##  Items you will want to change
##

#
# Location to scan for new images
#
IMAGE_DIR = "/Users/tomov90/Pictures/"
#
#   Flickr settings
#
FLICKR = {"title": "",
        "description": "",
        "tags": "auto-upload",
        "is_public": "0",
        "is_friend": "0",
        "is_family": "0" }
#
#   How often to check for new images to upload (in seconds)
#
SLEEP_TIME = 1 * 60
#
#   Only with --drip-feed option:
#     How often to wait between uploading individual images (in seconds)
#
DRIP_TIME = 1 * 60
#
#   File we keep the history of uploaded images in.
#
HISTORY_FILE = os.path.join(IMAGE_DIR, "uploadr.history")

##
##  You shouldn't need to modify anything below here
##
FLICKR["api_key"] = os.environ['FLICKR_UPLOADR_PY_API_KEY']
FLICKR["secret"] = os.environ['FLICKR_UPLOADR_PY_SECRET']
FLICKR["max_sets_per_page"] = 500
FLICKR["max_photos_per_page"] = 500

class APIConstants:
    """ APIConstants class
    """

    base = "http://flickr.com/services/"
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

class Uploadr:
    """ Uploadr class
    """

    token = None
    perms = ""
    TOKEN_FILE = os.path.join(IMAGE_DIR, ".flickrToken")
    sets = dict()   # full path -> id
    collections = dict()  # full path -> id

    image_fails = []
    set_fails = []
    collection_fails = []
    sets = dict()   # relative path -> id
    collections = dict()  # relative path -> id
    uploaded_images = dict() # relative path -> id

    image_fails = []
    set_fails = []
    collection_fails = []


    def __init__( self ):
        """ Constructor
        """
        self.token = self.getCachedToken()



    def signCall( self, data):
        """
        Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
        """
        keys = data.keys()
        keys.sort()
        foo = ""
        for a in keys:
            foo += (a + data[a])

        f = FLICKR[ api.secret ] + api.key + FLICKR[ api.key ] + foo
        #f = api.key + FLICKR[ api.key ] + foo
        return hashlib.md5( f ).hexdigest()

    def urlGen( self , base,data, sig ):
        """ urlGen
        """
        foo = base + "?"
        for d in data:
            foo += d + "=" + data[d] + "&"
        return foo + api.key + "=" + FLICKR[ api.key ] + "&" + api.sig + "=" + sig


    def authenticate( self ):
        """ Authenticate user so we can upload images
        """

        print("Getting new token")
        self.getFrob()
        self.getAuthKey()
        self.getToken()
        self.cacheToken()

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
            if ( self.isGood( response ) ):
                FLICKR[ api.frob ] = str(response.frob)
            else:
                self.reportError( response )
        except:
            print("Error getting frob:" + str( sys.exc_info() ))

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

    def getCachedToken( self ):
        """
        Attempts to get the flickr token from disk.
       """
        if ( os.path.exists( self.TOKEN_FILE )):
            return open( self.TOKEN_FILE ).read()
        else :
            return None



    def cacheToken( self ):
        """ cacheToken
        """

        try:
            open( self.TOKEN_FILE , "w").write( str(self.token) )
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

    # Crawlers

    def get_set( self, fullpath, photo_id ):
        p = fullpath.split('/')
        set_path = '/'.join(p[:-1])
        if not set_path in self.sets:
            if len(p) == 1:
                self.sets[set_path] = None
            else:
                set_name = p[-2]
                if len(p) == 2:
                    collection_name = None
                    collection_path = None
                else:
                    collection_path = '/'.join(p[:-2])
                    collection_name = collection_path

                # create set
                set_id = self.createSet(set_name, photo_id, set_path)
                self.sets[set_path] = set_id 

                # optionally add it to collection
                if collection_name:
                    # create collection
                    if not collection_path in self.collections:
                        self.collections[collection_path] = self.createCollection(collection_name, collection_path)
                    collection_id = self.collections[collection_path]
                    self.addSetToCollection(set_id, collection_id)

            #print 'Set ' + str(set_name)
            #print '    Path ' + set_path
            #print '           Collection ' + str(collection_path)
        return self.sets[set_path]

    def crawl( self ):
        if ( not self.checkToken() ):
            self.authenticate()

        start_path = IMAGE_DIR
        foo = os.walk(start_path)
        for data in foo:
            (dirpath, dirnames, filenames) = data
            for f in filenames :
                ext = f.lower().split(".")[-1]
                if ( ext == "jpg" or ext == "gif" or ext == "png" or ext == "jpeg" ):
                    fullpath = dirpath + "/" + f
                    relpath = fullpath[len(start_path):]

                    photo_id = self.uploadImage( fullpath, relpath )
                    if photo_id:
                        set_id = self.get_set(relpath, photo_id)
                        if set_id:
                            self.addImageToSet(photo_id, set_id)
                    if args.drip_feed and success and i != len( newImages )-1:
                        print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                        time.sleep( DRIP_TIME )

        print 'FAILED IMAGES = ' + str(self.image_fails)
        print 'FAILED SETS = ' + str(self.set_fails)
        print 'FAILED COLLECTIONS = ' + str(self.collection_fails)

    # API calls

    def getSets( self ):
        print("Getting all photo sets...")
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
                    print("Success page " + str(page))
                    if len(res[0]) == 0:
                        break
                    for nextset in res[0]:
                        set_name = nextset[0][0]
                        set_path = nextset[1][0]
                        set_id = nextset('id')
                        print 'Existing set ' + set_path + ' ---> ' + str(set_id)
                        self.sets[set_path] = set_id
                    success = True
                else :
                    print("Problem:")
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))

    def getCollections( self ):
        print("Getting all photo collections...")
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
                print("Success.")
                for collection in res[0]:
                    collection_name = collection('title')
                    collection_path = collection('description')
                    collection_id = collection('id')
                    print 'Existing collection ' + collection_path + ' ---> ' + str(collection_id)
                    self.collections[collection_path] = collection_id
                success = True
            else :
                print("Problem:")
                self.reportError( res )
        except:
            print(str(sys.exc_info()))

    def getUploadedPhotos( self ):
        print("Getting all uploaded photos...")
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
                    print("Success.")
                    if len(res[0]) == 0:
                        break
                    for image in res[0]:
                        image_name = image('title')
                        image_path = image[0][0]
                        image_id = image('id')
                        print 'Uploaded image ' + image_path + ' ---> ' + str(image_id)
                        self.uploaded_images[image_path] = image_id 
                    success = True
                else :
                    print("Problem:")
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))



    def createSet( self, name, image_id , description):
        set_id = None;
        print("Creating set " + name + " with image " + str(image_id) + ", desc = " + description)
        try:
            d = {
                api.token          : str(self.token),
                api.perms          : str(self.perms),
                "method"           : "flickr.photosets.create",
                "title"            : name,
                "description"      : description, 
                "primary_photo_id" : str(image_id)
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                print("Success.")
                set_id = res[0]('id')
                success = True
            else :
                print("Problem:")
                self.reportError( res )
                self.set_fails.append(description)
        except:
            print(str(sys.exc_info()))
        return set_id


    def addImageToSet( self, image_id, set_id ):
        success = False
        print("Adding image " + str(image_id) + " to set " + str(set_id) + "...")
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
                print("Success.")
                success = True
            else :
                print("Problem:")
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return success

    # unofficial api: http://stackoverflow.com/questions/2058025/adding-a-photo-collection-using-the-flickr-api
    def createCollection( self, name, description ):
        collection_id = None
        print("Creating collection " + name + " with desc = " + description)
        try:
            d = {
                api.token          : str(self.token),
                api.perms          : str(self.perms),
                "method"           : "flickr.collections.create",
                "title"            : name,
                "description"      : description
            }
            sig = self.signCall( d )
            d[ api.sig ] = sig
            d[ api.key ] = FLICKR[ api.key ]
            url = self.build_request(api.rest, d, ())
            xml = urllib2.urlopen( url ).read()
            res = xmltramp.parse(xml)
            if ( self.isGood( res ) ):
                print("Success.")
                collection_id = res[0]('id')
                success = True
            else :
                print("Problem:")
                self.collection_fails.append(description)
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return collection_id

    # unofficial API..... FTW
    def addSetToCollection( self, set_id , collection_id ):
        success = False
        print("Adding set " + str(set_id) + " to collection " + str(collection_id) + "...")
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
                print("Success.")
                success = True
            else :
                print("Problem:")
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return success

    def uploadImage( self, image, relpath ):

        photoid = None
        if not relpath in self.uploaded_images:
            print("Uploading " + image + "...")
            try:
                photo = ('photo', image, open(image,'rb').read())
                if args.title: # Replace
                    FLICKR["title"] = args.title
                if args.description: # Replace
                    FLICKR["description"] = args.description
                if args.tags: # Append
                    FLICKR["tags"] += " " + args.tags + " "
                d = {
                    api.token       : str(self.token),
                    api.perms       : str(self.perms),
                    "title"         : str( FLICKR["title"] ),
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
                    print("Success.")
                    photoid = res.photoid
                else :
                    print("Problem:")
                    self.reportError( res )
                    self.image_fails.append(image)
            except:
                print(str(sys.exc_info()))
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


    def run( self ):
        """ run
        """

        while ( True ):
            self.upload()
            print("Last check: " + str( time.asctime(time.localtime())))
            time.sleep( SLEEP_TIME )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Upload images to Flickr.')
    parser.add_argument('-d', '--daemon', action='store_true',
        help='Run forever as a daemon')
    parser.add_argument('-i', '--title',       action='store',
        help='Title for uploaded images')
    parser.add_argument('-e', '--description', action='store',
        help='Description for uploaded images')
    parser.add_argument('-t', '--tags',        action='store',
        help='Space-separated tags for uploaded images')
    parser.add_argument('-r', '--drip-feed',   action='store_true',
        help='Wait a bit between uploading individual images')
    args = parser.parse_args()

    flick = Uploadr()

    flick.getSets()
    flick.getCollections()
    flick.getUploadedPhotos()

    flick.crawl()
