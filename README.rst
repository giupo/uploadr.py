Uploadr.py
==========

Uploadr.py is a simple Python script for uploading your photos to Flickr. It also arranges them into 
sets and collections that correspond to the directory structure of your photos directory.


Instructions
==========

The script in its current version is only tested on Mac OS X so all instructions will be targeted to Mac users.


Step 0. Prerequisites
--------------

1. Python

Mac OS X 10.8 comes with Python preinstalled. To verfiy that, open a terminal and type ``python -V``.

2. Git

To see if you have Git installed, open a terminal and type ``git --version``. If you don’t have it, you can get the latest version from `here <https://code.google.com/p/git-osx-installer/downloads/list>`_.

Step 1. Download the script
---------------

Go to your favorite hacking directory and clone the repo::

	git clone https://github.com/tomov/uploadr.py

Then go to the script directory::

	cd uploadr.py/uploadr
	
Step 2. Run the script
---------------

Make sure to have your Flickr API key and secret (if you don't, you can get them `here <http://www.flickr.com/services/api/keys/apply/>`_). Then run the script::

	python uploadr.py --dir=[photos directory] --api-key=[your api key] --api-secret=[your api secret]

Here is how this would look for an example directory and api key and secret::

	python uploadr.py --dir="/Users/tomov90/Downloads/My Photos/" --api-key=00954e229265b619362cb462da234100 --api-secret=4cf2baa933309b8e

You will be forwarded to a Flickr confirmation page in your browser. Click ``OK, I'LL AUTHORIZE I`` at the bottom, go back to the terminal and type ``Y``

When you have got those keys, you need to set environment variables so that they
can be used by this application. For example, if you use Bash, add the following
lines to your ``$HOME/.bash_profile``::

    export FLICKR_UPLOADR_PY_API_KEY=0123456789abcdef0123456789abcdef
    export FLICKR_UPLOADR_PY_SECRET=0123456789abcdef


License
-------

Uploadr.py consists of code by Cameron Mallory, Martin Kleppmann, Aaron Swartz and
others. See ``COPYRIGHT`` for details.


Running Momchil's Version
--------------------

So I changed the code a bit to allow for collections and sets. Currently the script works like this:

1. You open uploadr.py and change IMAGE_DIR to wherever all your precious photos are

2. You run ``python uploadr.py``

3. The script will crawl the folder and all subfolders and upload all the images to your Flickr account

4. It will also order the images into sets and collections according to the directory structure, as follows:

The image with relative path ``Path/To/Some/Album/image.jpg`` will go into a photo set with the name ``Album`` (i.e. the name of the parent directory of the image) which in turn will go into a collection with the name ``Path/To/Some`` (i.e. the relative path of the parent directory of the image). Ideally, when some day Flickr releases their collections API, we will be able to create a collection ``Path`` and inside it a subcollection ``To`` and then a subsubcollection ``Some`` and then inside it a set ``Album`` and put the image there. For now though, I couldn't figure out how to do it, since the collections API is private.

5. The script avoids duplicate uploads based on the relative path of the images.

So in theory it is safe to interrupt it and run it again. Before it starts uploading anything, it scans all uploaded photos from your Flickr account and checks their relative paths (which are stored in the photo description -- please don't change that) to make sure it doesn't reupload them. Note that if you move stuff around in your photo directory or if you change the description attributes of images, sets, or collections in your Flickr account, the script may produce duplicate uploads. Also note that since all paths are relative, if you move your pictures folder somewhere else, everything should still work fine.

Also the code needs some cleaning up and I think I broke some of the originally available functionality, sorry about that. But the basic stuff seems to work. Please feel free to suggest improvements, or just fork and work on it yourself!
