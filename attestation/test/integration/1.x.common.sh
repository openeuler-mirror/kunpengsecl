### define some constant
oriHBDURATION="10s"
oriTRUSTDURATION="2m0s"
oriALLUPDATE=false
oriLOGTESTMODE=true
oriDBHOST="localhost"
oriDBNAME="kunpengsecl"
oriDBPASSWORD="postgres"
oriDBPORT=5432
oriDBUSER="postgres"
oriDIGESTALG="sha1"
oriMGRSTRATEGY="auto"
oriEXTRACTRULES='{\"PcrRule\":{\"PcrSelection\":[1,2,3,4]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"8-0\",\"80000008-1\"]},{\"MType\":\"ima\",\"Name\":[\"boot_aggregate\",\"/etc/modprobe.d/tuned.conf\"]}]}'
newDBNAME="testname"
newDBHOST="testhost"
newDBPORT=7531
newDBUSER="testuser"
newDBPASSWORD="testword"
newALLUPDATE=true
newLOGTESTMODE=false
newMGRSTRATEGY="manual"
newEXTRACTRULES='{\"PcrRule\":{\"PcrSelection\":[1,2]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"8-0\",\"80000008-2\"]},{\"MType\":\"ima\",\"Name\":[\"boot_aggregate\",\"/etc/modprobe.d/tuned.conf\"]}]}'
newHBDURATION="5s"
newTRUSTDURATION="20s"
newDIGESTALG="sha256"
NONREGISTER=false
strPCR="2 2ce976e4df6808c82fe206fac08f3acf012b0ec4\n2 c5e026af427eadae287b977035f49747e269e5a9\n3 c5e026af427eadae287b977035f49747e269e5a9\n4 d4dff43b56f1aacbecdae6c468d2cb7ffb27827e\n"
strBIOS="8-1 53933be89080c1fdc6352bb6c8e78799d01f2300 sha256:77e41e1a6e98f7160a8ba85d1b681df84b749f88ffd585612e145421b42ee581 N/A\n80000008-1 c6daaaf66efce12d87254eb5dc4bd2b8ad0dc085 sha256:723ed4cf5accf65d8fe684491d5cb1f6167f6315fa553d57fbf946667b07c2ad N/A\n"
strIMA="ima 6e7bbf27b7dd568610cc1f1ea49ceaa420395690 boot_aggregate\nima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca /etc/modprobe.d/tuned.conf\n"