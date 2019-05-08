## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
## 
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
## 

import argparse
import sys

from ropgadget.updateAlert import UpdateAlert
from ropgadget.version     import *

class Args(object):
    def __init__(self, binary=None):
        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--version",      action="store_true",              help="Display the ROPgadget's version")
        parser.add_argument("-c", "--checkUpdate",  action="store_true",              help="Checks if a new version is available")
        parser.add_argument("--binary",             type=str, metavar="<binary>",     help="Specify a binary filename to analyze")
        parser.add_argument("--opcode",             type=str, metavar="<opcodes>",    help="Search opcode in executable segment")
        parser.add_argument("--string",             type=str, metavar="<string>",     help="Search string in readable segment")
        parser.add_argument("--memstr",             type=str, metavar="<string>",     help="Search each byte in all readable segment")
        parser.add_argument("--depth",              type=int, metavar="<nbyte>",      default=10, help="Depth for search engine (default 10)")
        parser.add_argument("--only",               type=str, metavar="<key>",        help="Only show specific instructions")
        parser.add_argument("--filter",             type=str, metavar="<key>",        help="Suppress specific instructions")
        parser.add_argument("--range",              type=str, metavar="<start-end>",  default="0x0-0x0", help="Search between two addresses (0x...-0x...)")
        parser.add_argument("--badbytes",           type=str, metavar="<byte>",       help="Rejects specific bytes in the gadget's address")
        parser.add_argument("--rawArch",            type=str, metavar="<arch>",       help="Specify an arch for a raw file")
        parser.add_argument("--rawMode",            type=str, metavar="<mode>",       help="Specify a mode for a raw file")
        parser.add_argument("--re",                 type=str, metavar="<re>",         help="Regular expression")
        parser.add_argument("--offset",             type=str, metavar="<hexaddr>",    help="Specify an offset for gadget addresses")
        parser.add_argument("--ropchain",           action="store_true",              help="Enable the ROP chain generation")
        parser.add_argument("--thumb"  ,            action="store_true",              help="Use the thumb mode for the search engine (ARM only)")
        parser.add_argument("--console",            action="store_true",              help="Use an interactive console for search engine")
        parser.add_argument("--norop",              action="store_true",              help="Disable ROP search engine")
        parser.add_argument("--nojop",              action="store_true",              help="Disable JOP search engine")
        parser.add_argument("--callPreceded",       action="store_true",              help="Only show gadgets which are call-preceded")
        parser.add_argument("--nosys",              action="store_true",              help="Disable SYS search engine")
        parser.add_argument("--multibr",            action="store_true",              help="Enable multiple branch gadgets")
        parser.add_argument("--all",                action="store_true",              help="Disables the removal of duplicate gadgets")
        parser.add_argument("--dump",               action="store_true",              help="Outputs the gadget bytes")

        self.__args = parser.parse_args(None)

        self.__args.all = False
        self.__args.binary=binary
        self.__args.callPreceded=False
        self.__args.checkUpdate=None
        self.__args.console=False
        self.__args.depth=10
        self.__args.dump=False
        self.__args.filter=None
        self.__args.memstr=None
        self.__args.multibr=True
        self.__args.nojop=False
        self.__args.norop=False
        self.__args.nosys=False
        self.__args.offset=None
        self.__args.only=None
        self.__args.opcode=None
        self.__args.range='0x0-0x0'
        self.__args.rawArch=None
        self.__args.rawMode=None
        self.__args.re=None
        self.__args.ropchain=True
        self.__args.string=None
        self.__args.thumb=None
        self.__args.version=False

    def getArgs(self):
        return self.__args

