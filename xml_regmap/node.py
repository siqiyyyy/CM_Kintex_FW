from __future__ import print_function

import getopt
import sys
import os.path
import time
import logging
import math
import uhal

import StringIO
EXIT_CODE_INCORRECT_ARGUMENTS = 1
EXIT_CODE_ARG_PARSING_ERROR   = 2
EXIT_CODE_NODE_ADDRESS_ERRORS = 3
EXIT_CODE_NODE_INCONTINUITY = 4

class node(object):
    def __init__(self, uhalNode, baseAddress, tree=None, parent=None, index=None):
        self.parent = parent
        ##### reference to the tree class through parent
        self.tree = tree
        if self.parent:
            self.tree = self.parent.tree
        self.children = []
        #####
        self.id = uhalNode.getId()
        self.mask = uhalNode.getMask()
        self.description = uhalNode.getDescription()
        self.permission = self.readpermission(uhalNode.getPermission())
        self.fwinfo = uhalNode.getFirmwareInfo()
        absolute_address = uhalNode.getAddress()
        self.address = absolute_address - baseAddress
        ##### add children
        for childName in uhalNode.getNodes():
            ### TODO: are we filtering out registers whose ID contains a '.'?
            if childName.count('.')>0: continue
            childNode = uhalNode.getNode(childName)
            self.addChild(node(childNode, absolute_address, parent=self))
        ##### validate array type
        for child in self.children:
            if not child.checkContinuity(): 
                self.tree.log.critical("Critical: Attempting to register multiple array type registers but the indices are not continuous!")
                sys.exit(EXIT_CODE_NODE_INCONTINUITY)
        ##### sort children by address and id
        self.children = sorted(self.children, key=lambda child: (child.address, child.id))

    ### usually allow first layer nodes to have different address etc. but require all children to be exactly same
    def isIdentical(self,other,compareAll=False):
        ##### check attributes for the first level
        if not self.parent == other.parent: return False
        if not self.tree == other.tree: return False
        if not self.permission == other.permission: return False
        if not self.fwinfo == other.fwinfo: return False
        ##### stricter check for deeper levels
        if compareAll:
            if not self.id == other.id: return False
            if not self.address == other.address: return False
            if not self.mask == other.mask: return False
            if not self.description == other.description: return False
        ##### compare children, assuming they are sorted by address and id already!
        if not len(self.children) == len(other.children): return False
        for i_children in range(len(self.children)):
            if not self.children[i_children].isIdentical(other.children[i_children],compareAll=True): return False
        return True

    def addChild(self,child):
        array_index = child.extract_index()
        if array_index >= 0: #### treat it as an array type
            ##### check if it should be appended to an existing child
            for other_child in self.children:
                if other_child.isArray() and other_child.checkAppend(child):
                    return
            ##### otherwise create a new array 
            self.children.append(array_node(child))
            return
        self.children.append(child)
        return

    def isArray(self):
        return self.__class__ == array_node

    ### re-implemented in array_node class
    def checkContinuity(self):
        return True
    
    ### returns the array index if id in the format "name_index" and has "type=array" in fw info, otherwise -1
    ### example: <node id="CM_1" fwinfo="type=array">
    def extract_index(self):
        if not 'type' in self.fwinfo.keys():
            return -1
        if not "array" in self.fwinfo['type']:
            return -1
        index_string = self.id[self.id.rfind('_')+1:]
        try:
            index=int(index_string)
        except ValueError:
            return -1
        return index
        
    @staticmethod
    def readpermission(permission):
        if permission == uhal.NodePermission.READ: 
            return 'r'
        elif permission == uhal.NodePermission.READWRITE: 
            return 'rw'
        elif permission == uhal.NodePermission.WRITE: 
            return 'w'
        else:
            return ""

    @staticmethod
    def getBitRange(mask):
        bits = bin(mask)[2:].zfill(32)[::-1]
        start = -1
        end = -1    
        for i in range(len(bits)-1,-1,-1):
            if start == -1:
                if bits[i] == '1':
                    start = i
            elif end == -1:
                if bits[i] == '0' :
                    end = i+1
                    break
        if end == -1:
            end = 0
        if start == end:
            return str(start).rjust(2)
        else:
            return str(start).rjust(2,' ') +" downto "+str(end).rjust(2,' ')

class array_node(node):
    ##### initialized with the first entry
    def __init__(self, first_entry):
        first_index = first_entry.extract_index()
        assert first_index >= 0
        self.id = first_entry.id[:first_entry.id.rfind('_')]
        self.description = "Array of " + self.id
        self.address = first_entry.address
        self.mask = 0xffffffff
        self.fwinfo = first_entry.fwinfo
        self.permission = first_entry.permission
        self.parent = first_entry.parent
        self.tree = first_entry.tree
        self.children = first_entry.children
        self.entries = {first_index : first_entry}
    
    def isCompatible(self, new_entry):
        new_index = new_entry.extract_index()
        if (new_index < 0) or (new_index in self.entries.keys()): return False
        if not self.id == new_entry.id[:new_entry.id.rfind('_')]: return False
        if not self.isIdentical(new_entry): return False 
        return True

    ### If new entry is compatible, add it to the array and return True, otherwise return False
    def checkAppend(self, new_entry):
        if self.isCompatible(new_entry):
            new_index = new_entry.extract_index()
            self.entries[new_index] = new_entry
            return True
        return False

    def checkContinuity(self):
        keys = list(self.entries.keys())
        return ( sorted(keys) == list(range(min(keys),max(keys)+1)) )


        

class tree(object):
    def __init__(self, root, logger=None):
        self.read_ops = dict(list())
        self.readwrite_ops = str()
        self.write_ops = dict(list())
        self.action_ops = str()
        ##### setup logger
        self.log = logger
        if not self.log:
            self.log = logging.getLogger("main")
            formatter = logging.Formatter('%(name)s %(levelname)s: %(message)s')
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
            self.log.addHandler(handler)
            self.log.setLevel(logging.WARNING)
            uhal.setLogLevelTo(uhal.LogLevel.WARNING)
        ##### read the root node
        self.root = node(root,baseAddress=0,tree=self)
